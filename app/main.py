import os
import base64
import html
import json
import re
import secrets
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

BACKEND = os.getenv("BACKEND_URL", "http://10.17.1.201:38080")

# 网关对外暴露的 MCP 路径（映射到后端 /api/v1/main/mcp）
MCP_PREFIX = "/api/v2/main/mcp"

# Kestra 后端的 MCP 路径
BACKEND_MCP_PREFIX = "/api/v1/main/mcp"

# 原有后端 Basic Auth
BACKEND_AUTH = os.getenv("KESTRA_BASIC_AUTH", "")

# 新的 Gateway Basic Auth
GATEWAY_USER = os.getenv("GATEWAY_USER", "u041007")
GATEWAY_PASSWORD = os.getenv("GATEWAY_PASSWORD", "")


def _parse_gateway_users() -> dict:
    """解析 GATEWAY_USERS：格式为 账号:密码,账号:密码（每个账号各自密码）"""

    users = {}

    for item in os.getenv("GATEWAY_USERS", "").split(","):
        item = item.strip()

        if not item or ":" not in item:
            continue

        account, password = item.split(":", 1)
        account = account.strip()

        if account:
            users[account] = password

    return users


# 各账号独立密码
GATEWAY_USERS = _parse_gateway_users()

# 兼容单账号配置
if not GATEWAY_USERS and GATEWAY_USER:
    GATEWAY_USERS = {GATEWAY_USER: GATEWAY_PASSWORD}

# Cerbos PDP 地址
CERBOS_URL = os.getenv("CERBOS_URL", "").rstrip("/")

# Kestra 租户（写死 main，OSS 单租户）
KESTRA_TENANT = "main"

# 受保护账号（需要 Cerbos 额外授权）
PROTECTED_TARGETS = {"u041007", "u199013"}

# 管理 API 的 HTTP 方法 -> Cerbos action
API_ACTIONS = {
    "GET": "read",
    "HEAD": "read",
    "OPTIONS": "read",
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}

# 展示時區（UTC+8）
DISPLAY_TZ = timezone(timedelta(hours=8))

# 统计：执行记录拉取与缓存
STATS_PAGE_SIZE = 1000
STATS_MAX_PAGES = 20
STATS_CACHE_TTL = int(os.getenv("STATS_CACHE_TTL", "30"))
STATS_WINDOW_HOURS = int(os.getenv("STATS_WINDOW_HOURS", "24"))
STATS_TOP = int(os.getenv("STATS_TOP", "10"))

_stats_cache = {"at": 0.0, "data": None}

app = FastAPI(title="MCP PDP Gateway")

client = httpx.AsyncClient(
    timeout=httpx.Timeout(300, connect=15),
)


@app.on_event("shutdown")
async def shutdown():
    await client.aclose()


def authenticate(request: Request):
    """校验 Gateway Basic Auth，返回访问者账号（Cerbos principal id）"""

    auth = request.headers.get("Authorization", "")

    if not auth.startswith("Basic "):
        return None

    try:
        decoded = base64.b64decode(
            auth[6:], validate=True
        ).decode()

        username, password = decoded.split(":", 1)

    except Exception:
        return None

    account = username.strip() or GATEWAY_USER

    expected = GATEWAY_USERS.get(account)

    if not expected or not secrets.compare_digest(password, expected):
        return None

    return account


def client_ip(request: Request):
    """取访问者来源 IP：X-Forwarded-For 首跳 -> X-Real-IP -> TCP 对端地址

    注意：X-Forwarded-For 可被客户端伪造，必须由可信反向代理覆盖该头，
    否则策略里的来源 IP 判断不可信。
    """

    forwarded = request.headers.get("x-forwarded-for")

    if forwarded:
        first = forwarded.split(",")[0].strip()

        if first:
            return first

    real_ip = request.headers.get("x-real-ip")

    if real_ip:
        return real_ip.strip()

    return request.client.host if request.client else None


async def cerbos_allow(
    principal_id: str,
    resource_id: str,
    action: str,
    kind: str = "kestra-mcp",
    ip: str = None,
) -> bool:
    """调用 Cerbos PDP，判断 principal 是否有权对资源执行 action"""

    if not CERBOS_URL:
        return False

    principal = {
        "id": principal_id,
        "roles": ["user"],
        "policyVersion": "default",
    }

    # 来源 IP 作为可选属性传给策略
    if ip:
        principal["attr"] = {"ip": ip}

    payload = {
        "requestId": f"{principal_id}-{kind}-{resource_id}",
        "principal": principal,
        "resources": [
            {
                "resource": {"kind": kind, "id": resource_id},
                "actions": [action],
            }
        ],
    }

    try:
        response = await client.post(
            f"{CERBOS_URL}/api/check/resources",
            json=payload,
            timeout=httpx.Timeout(5.0, connect=3.0),
        )
        response.raise_for_status()
        data = response.json()

    except Exception:
        # Cerbos 不可用时按拒绝处理（fail closed）
        return False

    results = data.get("results") or []

    if not results:
        return False

    actions = results[0].get("actions") or {}

    return actions.get(action) == "EFFECT_ALLOW"


def requested_tenant(request: Request):
    """取客户端请求的租户（X-Kestra-Tenant 头或 tenant 查询参数）"""

    tenant = request.headers.get("x-kestra-tenant")

    if not tenant:
        tenant = request.query_params.get("tenant")

    return tenant.strip() if tenant else None


def ensure_tenant(request: Request):
    """客户端请求的租户必须与网关配置的租户一致"""

    tenant = requested_tenant(request)

    if tenant and tenant != KESTRA_TENANT:
        raise HTTPException(
            status_code=400,
            detail=f"Tenant must be '{KESTRA_TENANT}'",
        )


def flow_id_from_body(request: Request, body: bytes):
    """从创建 flow 的请求体（YAML/JSON）中取出 flow id"""

    if not body:
        return None

    content_type = (request.headers.get("content-type") or "").lower()

    if "json" in content_type:
        try:
            payload = json.loads(body)
        except Exception:
            return None

        if isinstance(payload, dict):
            flow = payload.get("flow") if isinstance(payload.get("flow"), dict) else payload
            return flow.get("id")

        return None

    # YAML：取顶层的 id 字段
    match = re.search(
        r"(?m)^id:\s*[\"']?([^\s\"']+)",
        body.decode("utf-8", "replace"),
    )

    return match.group(1) if match else None


def extract_flow_id(request: Request, rest: str, body: bytes):
    """提取请求涉及到的 flow id（命名空间列表等无 flow id 的请求返回 None）"""

    parts = [p for p in rest.split("/") if p]

    # 去掉可选的租户前缀（如 main/），避免绕过 flow 归属校验
    while parts and parts[0] == KESTRA_TENANT:
        parts = parts[1:]

    if "flows" not in parts:
        return None

    index = len(parts) - 1 - parts[::-1].index("flows")
    after = parts[index + 1:]

    # flows/{namespace}/{flowId}[/...]
    if len(after) >= 2:
        return after[1]

    # flows/{namespace}：命名空间级别的列表，不涉及单个 flow
    if len(after) == 1:
        return None

    # flows：创建 flow，flow id 在请求体里
    return flow_id_from_body(request, body)


def _targets_flows(rest: str):
    """请求路径是否指向 flow 资源"""

    parts = [p for p in rest.split("/") if p]

    while parts and parts[0] == KESTRA_TENANT:
        parts = parts[1:]

    return "flows" in parts


def ensure_flow_owner(account: str, flow_id):
    """flow id 必须以 "<账号>_" 前缀开头，否则禁止控制"""

    if not flow_id:
        return

    if not flow_id.startswith(f"{account}_"):
        raise HTTPException(
            status_code=403,
            detail=f"Flow id must be prefixed with '{account}_'",
        )


async def proxy_to_backend(request: Request, path: str) -> StreamingResponse:
    """转发请求到 Kestra 后端，并注入后端 Basic Auth"""

    # 转发时去掉客户端指定的 tenant，统一由网关注入
    query = [
        (k, v)
        for k, v in request.query_params.multi_items()
        if k.lower() != "tenant"
    ]

    url = BACKEND + path

    if query:
        url += "?" + urlencode(query)

    # 覆盖客户端的 Authorization，使用后端原有认证
    headers = dict(request.headers)

    headers.pop("host", None)
    headers.pop("authorization", None)
    headers.pop("content-length", None)
    headers.pop("x-kestra-tenant", None)

    if BACKEND_AUTH:
        headers["Authorization"] = (
            "Basic " + BACKEND_AUTH
        )

    headers["X-Kestra-Tenant"] = KESTRA_TENANT

    body = await request.body()

    upstream_request = client.build_request(
        method=request.method,
        url=url,
        headers=headers,
        content=body,
    )

    upstream = await client.send(
        upstream_request,
        stream=True,
    )

    # SSE/MCP 流式响应透传
    response_headers = {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() not in {
            "transfer-encoding",
            "connection",
            "keep-alive",
        }
    }

    return StreamingResponse(
        upstream.aiter_raw(),
        status_code=upstream.status_code,
        headers=response_headers,
        background=BackgroundTask(upstream.aclose),
    )


def backend_headers():
    """访问 Kestra 后端所需请求头"""

    headers = {"X-Kestra-Tenant": KESTRA_TENANT}

    if BACKEND_AUTH:
        headers["Authorization"] = "Basic " + BACKEND_AUTH

    return headers


async def fetch_executions():
    """拉取后端执行记录（该 Kestra 版本不支持服务端过滤，客户端自行统计）"""

    headers = backend_headers()

    results = []
    total = 0

    for page in range(1, STATS_MAX_PAGES + 1):
        response = await client.get(
            f"{BACKEND}/api/v1/executions/search",
            params={"size": STATS_PAGE_SIZE, "page": page},
            headers=headers,
            timeout=httpx.Timeout(30.0, connect=5.0),
        )
        response.raise_for_status()

        data = response.json()
        batch = data.get("results") or []

        results.extend(batch)
        total = data.get("total", total)

        if not batch or len(results) >= total:
            break

    return results, total


async def fetch_flows():
    """拉取 flow 清单统计（总数与按命名空间分布）"""

    try:
        response = await client.get(
            f"{BACKEND}/api/v1/flows/search",
            params={"size": 500},
            headers=backend_headers(),
            timeout=httpx.Timeout(15.0, connect=5.0),
        )
        response.raise_for_status()

        data = response.json()
        results = data.get("results") or []

        by_namespace = Counter(
            item.get("namespace") for item in results if item.get("namespace")
        )

        return {
            "total": data.get("total", len(results)),
            "listed": len(results),
            "by_namespace": dict(by_namespace),
        }

    except Exception:
        return {"total": None, "listed": 0, "by_namespace": {}}


def parse_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))

    except Exception:
        return None


def parse_duration(value):
    """ISO-8601 duration -> 秒"""

    if not value:
        return None

    match = re.match(
        r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?)?$",
        str(value),
    )

    if not match:
        return None

    days, hours, minutes, seconds = match.groups()

    return (
        int(days or 0) * 86400
        + int(hours or 0) * 3600
        + int(minutes or 0) * 60
        + float(seconds or 0)
    )


def summarize(states):
    """按状态汇总"""

    success = states.get("SUCCESS", 0)
    failed = states.get("FAILED", 0)
    running = states.get("RUNNING", 0)
    pending = states.get("CREATED", 0)
    paused = states.get("PAUSED", 0)

    finished = success + failed

    return {
        "total": sum(states.values()),
        "success": success,
        "failed": failed,
        "running": running,
        "pending": pending,
        "paused": paused,
        "other": sum(states.values()) - success - failed - running - pending - paused,
        "finished": finished,
        "success_ratio": round(success / finished, 4) if finished else None,
    }


async def collect_stats(window_hours: int, top: int):
    """统计执行情况（带缓存，避免频繁拉取全量执行记录）"""

    now = time.time()

    if _stats_cache["data"] and now - _stats_cache["at"] < STATS_CACHE_TTL:
        executions, total, fetched_at, flow_inventory = _stats_cache["data"]

    else:
        started = time.perf_counter()
        executions, total = await fetch_executions()
        flow_inventory = await fetch_flows()
        fetched_at = {
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "records": len(executions),
        }
        _stats_cache["at"] = now
        _stats_cache["data"] = (executions, total, fetched_at, flow_inventory)

    # 以当前时间为终点的 24 小时刻度（24 小时制，整点对齐）
    now = datetime.now(DISPLAY_TZ)
    end_hour = now.replace(minute=0, second=0, microsecond=0)
    slot_keys = [
        (end_hour - timedelta(hours=index)).strftime("%m-%d %H:00")
        for index in range(23, -1, -1)
    ]

    cutoff = end_hour - timedelta(hours=23)

    all_states = Counter()
    window_states = Counter()
    by_namespace = defaultdict(Counter)
    by_flow = defaultdict(Counter)
    last_run = {}
    hourly = {key: Counter() for key in slot_keys}
    durations = []
    active_flows = set()

    for execution in executions:
        state = execution.get("state") or {}
        current = state.get("current") or "UNKNOWN"
        namespace = execution.get("namespace")
        flow_id = execution.get("flowId")

        all_states[current] += 1
        by_namespace[namespace][current] += 1
        by_flow[(namespace, flow_id)][current] += 1

        started_at = parse_datetime(state.get("startDate"))

        if started_at is None:
            histories = state.get("histories") or []
            started_at = parse_datetime(histories[0].get("date")) if histories else None

        if started_at is None:
            continue

        key = (namespace, flow_id)

        local_time = started_at.astimezone(DISPLAY_TZ).isoformat()

        if local_time > last_run.get(key, ""):
            last_run[key] = local_time

        if started_at >= cutoff:
            window_states[current] += 1
            active_flows.add(key)

            bucket_key = started_at.astimezone(DISPLAY_TZ).strftime("%m-%d %H:00")

            if bucket_key in hourly:
                hourly[bucket_key][current] += 1

            if current in ("SUCCESS", "FAILED"):
                seconds = parse_duration(state.get("duration"))

                if seconds is not None:
                    durations.append(seconds)

    durations.sort()

    def percentile(percent):
        if not durations:
            return None

        index = min(len(durations) - 1, int(round((percent / 100) * (len(durations) - 1))))

        return round(durations[index], 3)

    flow_stats = []

    for (namespace, flow_id), states in by_flow.items():
        item = summarize(states)
        item["namespace"] = namespace
        item["flow_id"] = flow_id
        item["last_run"] = last_run.get((namespace, flow_id))
        flow_stats.append(item)

    flow_stats.sort(key=lambda item: (item["total"], item["last_run"] or ""), reverse=True)

    window_total = sum(window_states.values())

    return {
        "generated_at": datetime.now(DISPLAY_TZ).isoformat(),
        "window": {
            "hours": window_hours,
            "from": cutoff.isoformat(),
            "to": datetime.now(DISPLAY_TZ).isoformat(),
        },
        "executions": {
            "window": summarize(window_states),
            "all_time": summarize(all_states),
            "all_time_total": total,
        },
        "by_namespace": {
            namespace: summarize(states) for namespace, states in by_namespace.items()
        },
        "top_flows": flow_stats[:top],
        "hourly": {
            bucket: summarize(states) for bucket, states in sorted(hourly.items())
        },
        "flow_inventory": flow_inventory,
        "summary": {
            "active_flows": len(active_flows),
            "rate_per_minute": round(window_total / (window_hours * 60), 2) if window_hours else 0,
            "avg_duration_s": round(sum(durations) / len(durations), 3) if durations else None,
            "p50_duration_s": percentile(50),
            "p95_duration_s": percentile(95),
            "max_duration_s": round(durations[-1], 3) if durations else None,
        },
        "fetch": fetched_at,
    }


DASHBOARD_CSS = """
:root{
  --bg:#eef2f9; --ink:#141d31; --muted:#6b7890; --line:#e2e8f4;
  --blue:#2f6fed; --violet:#7a5cf0; --teal:#12b3a3; --green:#1fa971;
  --amber:#f5a524; --rose:#e5484d; --cyan:#0ea5e9;
}
*{box-sizing:border-box;scrollbar-width:thin}
html{scroll-behavior:smooth}
body{margin:0;color:var(--ink);font:14px/1.55 system-ui,-apple-system,"Segoe UI","PingFang TC","Microsoft JhengHei",sans-serif;
  background:radial-gradient(1200px 600px at 8% -10%,#dbe7ff 0%,transparent 55%),
             radial-gradient(1000px 520px at 92% 0%,#e6dcff 0%,transparent 52%),
             radial-gradient(900px 480px at 50% 110%,#d8f7f1 0%,transparent 55%),var(--bg)}

header{position:sticky;top:0;z-index:30;color:#fff;padding:16px max(20px,calc((100vw - 1500px)/2));
  background:linear-gradient(100deg,#0b1e3c 0%,#1d3f7d 45%,#3a2f8f 78%,#0f6f8f 100%);
  background-size:220% 100%;animation:sheen 14s ease-in-out infinite alternate;
  box-shadow:0 6px 22px rgba(12,28,58,.28);border-bottom:3px solid rgba(255,255,255,.18);
  display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap}
@keyframes sheen{0%{background-position:0% 50%}100%{background-position:100% 50%}}
header h1{margin:0;font-size:23px;letter-spacing:.2px;display:flex;align-items:center;gap:10px}
header h1 span{width:10px;height:10px;border-radius:50%;background:#4ade80;box-shadow:0 0 0 0 rgba(74,222,128,.7);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(74,222,128,.65)}70%{box-shadow:0 0 0 12px rgba(74,222,128,0)}100%{box-shadow:0 0 0 0 rgba(74,222,128,0)}}
header p{color:#c6d8f5;margin:5px 0 0;font-size:13px}
.badge{display:inline-flex;align-items:center;gap:8px;padding:8px 18px;border-radius:22px;font-size:12.5px;letter-spacing:.3px;
  border:1px solid rgba(255,255,255,.28);background:rgba(255,255,255,.12);backdrop-filter:blur(6px);color:#e6f0ff}
.badge b{color:#fff;font-weight:700;letter-spacing:.6px}
.badge.bad{background:rgba(229,72,77,.28);border-color:rgba(255,180,180,.5)}

main{max-width:1500px;margin:22px auto;padding:0 18px}
.cards{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:13px}
@media (max-width:1280px){.cards{grid-template-columns:repeat(4,minmax(0,1fr))}}
@media (max-width:900px){.cards{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:640px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}}
.card{position:relative;overflow:hidden;background:#fff;border:1px solid var(--line);border-radius:14px;padding:15px 16px;
  box-shadow:0 2px 8px rgba(20,40,80,.05);opacity:1;transform:none;animation:rise .5s ease both}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.card::before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:linear-gradient(180deg,var(--accent,#2f6fed),transparent)}
.card:hover{transform:translateY(-3px);box-shadow:0 12px 26px rgba(20,40,80,.14);transition:transform .18s ease,box-shadow .18s ease}
.card small{display:block;color:var(--muted);font-size:12px;letter-spacing:.2px}
.card strong{display:block;font-size:27px;margin-top:6px;font-variant-numeric:tabular-nums;letter-spacing:-.5px}
.card small.sub{margin-top:5px;font-size:11px;color:#8794ab}
.card.blue{--accent:var(--blue)}.card.violet{--accent:var(--violet)}.card.teal{--accent:var(--teal)}
.card.green{--accent:var(--green)}.card.amber{--accent:var(--amber)}.card.rose{--accent:var(--rose)}
.card.cyan{--accent:var(--cyan)}

.panel{background:#fff;border:1px solid var(--line);border-radius:14px;padding:16px;margin-top:16px;overflow:hidden;
  box-shadow:0 2px 8px rgba(20,40,80,.05)}
.panel h2{margin:0 0 12px;font-size:15px;color:#22304d;display:flex;align-items:center;gap:8px;white-space:nowrap}
.panel h2 i{width:8px;height:16px;border-radius:4px;background:linear-gradient(180deg,var(--blue),var(--violet));display:inline-block}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(430px,1fr));gap:16px;align-items:stretch}
.grid2 .panel{margin-top:16px;display:flex;flex-direction:column;min-height:372px}
.grid2 .panel h2{flex:0 0 auto}
.panel.pstate .summary{flex:1 1 auto;align-items:center}
.panel.pchart .chart{flex:1 1 auto;min-height:170px}
.panel.pchart .legend{flex:0 0 auto}

.summary{display:flex;gap:22px;align-items:center;flex-wrap:wrap}
.donut{position:relative;width:132px;height:132px;border-radius:50%;flex:0 0 auto;
  background:conic-gradient(var(--green) 0 calc(var(--p,0)*1%),var(--rose) calc(var(--p,0)*1%) 100%);
  transform:none;opacity:1;animation:spinin .9s cubic-bezier(.2,.8,.2,1) both}
@keyframes spinin{from{transform:rotate(-90deg) scale(.86);opacity:.2}to{transform:none;opacity:1}}
.donut::after{content:"";position:absolute;inset:15px;border-radius:50%;background:#fff}
.donut em{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;
  font-style:normal;font-weight:700;font-size:22px;z-index:2;font-variant-numeric:tabular-nums}
.donut em small{font-size:11px;color:var(--muted);font-weight:500}
.kv{display:grid;grid-template-columns:auto auto;gap:6px 18px;font-size:13px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;font-weight:600;font-variant-numeric:tabular-nums;text-align:right}

.distbar{display:flex;height:16px;border-radius:9px;overflow:hidden;background:#eef1f7;margin:4px 0 10px}
.distbar i{display:block;height:100%;transition:width .8s cubic-bezier(.2,.8,.2,1)}
.distbar .ok{background:linear-gradient(90deg,#34c98a,#1fa971)}
.distbar .bad{background:linear-gradient(90deg,#f0706d,#e5484d)}
.distbar .run{background:linear-gradient(90deg,#7dd3fc,#0ea5e9)}
.distbar .pend{background:linear-gradient(90deg,#fcd34d,#f5a524)}
.distbar .other{background:linear-gradient(90deg,#cbd5e1,#94a3b8)}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--muted)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}

.chart{display:flex;align-items:flex-end;gap:4px;height:178px;padding:10px 2px 18px;overflow:hidden;width:100%}
.chart .col{flex:1 1 0;min-width:0;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:4px;height:100%;cursor:default;overflow:visible}
.chart .stack{width:100%;max-width:26px;display:flex;flex-direction:column;justify-content:flex-end;height:100%;
  transform-origin:bottom;transform:scaleY(1);animation:grow .7s cubic-bezier(.2,.8,.2,1) both}
@keyframes grow{from{transform:scaleY(0)}to{transform:scaleY(1)}}
.chart .seg{width:100%}
.chart .seg.ok{background:linear-gradient(180deg,#4fd39b,#1fa971)}
.chart .seg.bad{background:linear-gradient(180deg,#f47874,#e5484d)}
.chart .seg.other{background:linear-gradient(180deg,#d7dfec,#aab6c8)}
.chart .col:hover .stack{filter:brightness(1.08) saturate(1.2)}
.chart small{font-size:10px;color:#8b96a8;white-space:nowrap;height:15px;line-height:15px;transform:none;overflow:visible}

.tablewrap{max-height:360px;overflow:auto;border:1px solid var(--line);border-radius:10px;background:#fff}
.tablewrap{scrollbar-color:transparent transparent}
.tablewrap::-webkit-scrollbar{width:6px;height:6px;background:transparent}
.tablewrap::-webkit-scrollbar-track{background:transparent}
.tablewrap::-webkit-scrollbar-thumb{background:transparent;border-radius:4px}
.tablewrap::-webkit-scrollbar-thumb:hover{background:transparent}
.tablewrap::-webkit-scrollbar-corner{background:transparent}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px}
th,td{text-align:left;padding:9px 11px;white-space:nowrap}
thead th{position:sticky;top:0;z-index:1;color:#5c6a83;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.7px;
  background:linear-gradient(180deg,#f8fafd,#eef2f9);border-bottom:1px solid #dde4f0}
tbody td{border-bottom:1px solid #eff2f8;color:#3a4761}
tbody tr:nth-child(odd){background:#f9fbfe}
tbody tr:nth-child(even){background:#fff}
tbody tr{transition:background .16s ease,box-shadow .16s ease}
tbody tr:hover{background:#eaf1ff}
tbody tr:hover td:first-child{box-shadow:inset 3px 0 0 var(--blue)}
tbody tr:last-child td{border-bottom:none}
td.num{text-align:right;font-variant-numeric:tabular-nums}
td.num:first-child{text-align:left}
tbody td:first-child{font-weight:600;color:#2c3a56}
.bar{height:8px;border-radius:5px;background:#eef1f7;overflow:hidden;min-width:110px}
.bar i{display:block;height:100%;border-radius:5px;background:linear-gradient(90deg,#34c98a,#1fa971);
  transition:width .9s cubic-bezier(.2,.8,.2,1)}
.bar.bad i{background:linear-gradient(90deg,#f0706d,#e5484d)}
.tag{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;background:#eef2fb;color:#3d5ea8}
.mask{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#54627a;letter-spacing:.4px}
footer{max-width:1500px;margin:18px auto 30px;padding:0 18px;color:#8794ab;font-size:12px}
@media (max-width:640px){.summary{gap:14px}.donut{width:104px;height:104px}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

DASHBOARD_JS = """
(function(){
  function animate(el){
    var raw = el.getAttribute('data-count');
    if(raw === null) return;
    var target = parseFloat(raw);
    if(isNaN(target)) return;
    var dec = (el.getAttribute('data-dec') || '0') | 0;
    var start = performance.now(), dur = 900;
    function step(now){
      var p = Math.min(1, (now - start) / dur);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = (target * eased).toFixed(dec);
      if(p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  document.querySelectorAll('[data-count]').forEach(animate);
})();
"""


def format_ratio(value):
    return "-" if value is None else f"{value * 100:.2f}%"


def format_duration(seconds):
    if seconds is None:
        return "-"

    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"

    if seconds < 60:
        return f"{seconds:.2f} s"

    return f"{seconds / 60:.1f} min"


def mask_name(value, keep=3):
    """遮罩細節：只保留前幾個字元"""

    if not value:
        return "-"

    text = str(value)

    if len(text) <= keep:
        return text[0] + "*" * max(1, len(text) - 1)

    return text[:keep] + "*" * max(3, len(text) - keep)


def mask_time(value):
    """遮罩時間：只保留日期與時分"""

    if not value:
        return "-"

    text = str(value)

    if len(text) >= 16:
        return text[5:16].replace("T", " ")

    return text


def render_dashboard(data):
    """渲染執行狀態儀表板（純 HTML/CSS/JS，無外部依賴）"""

    backend = data.get("backend") or {}
    executions = data.get("executions") or {}
    window = executions.get("window") or {}
    all_time = executions.get("all_time") or {}
    by_namespace = data.get("by_namespace") or {}
    top_flows = data.get("top_flows") or []
    hourly = data.get("hourly") or {}
    inventory = data.get("flow_inventory") or {}
    summary = data.get("summary") or {}

    healthy = data.get("status") == "ok"
    status_text = "正常" if healthy else "降級"

    cards = [
        ("blue", "24 小時執行", window.get("total", 0), "視窗內執行總數", 0),
        ("green", "成功率", format_ratio(window.get("success_ratio")), "成功 ÷ 已完成", None),
        ("rose", "失敗", window.get("failed", 0), "FAILED", 0),
        ("cyan", "進行中", window.get("running", 0), "RUNNING", 0),
        ("amber", "待處理", window.get("pending", 0), "CREATED", 0),
        ("violet", "已暫停", window.get("paused", 0), "PAUSED", 0),
        ("teal", "執行速率", summary.get("rate_per_minute", 0), "次 / 分鐘", 2),
        ("blue", "平均耗時", format_duration(summary.get("avg_duration_s")), "窗口內完成執行", None),
        ("violet", "P95 耗時", format_duration(summary.get("p95_duration_s")), "窗口內完成執行", None),
        ("teal", "活躍 Flow", summary.get("active_flows", 0), "窗口內有執行", 0),
        ("cyan", "Flow 總數", inventory.get("total") or 0, "命名空間內 flow 總量", 0),
        ("green", "累計執行", all_time.get("total", 0), "全部歷史", 0),
    ]

    card_html = []

    for index, (accent, title, value, sub, decimals) in enumerate(cards):
        if decimals is None:
            value_html = html.escape(str(value))
        else:
            value_html = (
                f'<span data-count="{html.escape(str(value))}" '
                f'data-dec="{decimals}">{html.escape(str(value))}</span>'
            )

        card_html.append(
            f'<div class="card {accent}" style="animation-delay:{index * 45}ms">'
            f"<small>{html.escape(title)}</small>"
            f"<strong>{value_html}</strong>"
            f'<small class="sub">{html.escape(sub)}</small></div>'
        )

    total_window = window.get("total", 0) or 1

    def pct(value):
        return round((value or 0) / total_window * 100, 1)

    dist = [
        ("ok", "成功", window.get("success", 0)),
        ("bad", "失敗", window.get("failed", 0)),
        ("run", "進行中", window.get("running", 0)),
        ("pend", "待處理", window.get("pending", 0)),
        ("other", "其它", window.get("other", 0)),
    ]

    dist_bars = "".join(
        f'<i class="{cls}" style="width:{pct(value)}%"></i>' for cls, _, value in dist
    )

    dist_legend = "".join(
        f'<span><i style="background:{color}"></i>{html.escape(label)} {value}'
        f'（{pct(value)}%）</span>'
        for (cls, label, value), color in zip(
            dist,
            ["#1fa971", "#e5484d", "#0ea5e9", "#f5a524", "#94a3b8"],
        )
    )

    peak = max([item.get("total", 0) for item in hourly.values()] or [1]) or 1

    bars = []

    for index, (bucket, item) in enumerate(hourly.items()):
        total = item.get("total", 0) or 1
        ok_h = round(item.get("success", 0) / total * 100, 1)
        bad_h = round(item.get("failed", 0) / total * 100, 1)
        other_h = max(0.0, 100 - ok_h - bad_h)
        height = max(3, round(item.get("total", 0) / peak * 100, 1))

        bars.append(
            f'<div class="col" title="{html.escape(bucket)}｜成功 {item.get("success", 0)}'
            f'｜失敗 {item.get("failed", 0)}｜合計 {item.get("total", 0)}">'
            f'<div class="stack" style="height:{height}%;animation-delay:{index * 35}ms">'
            f'<div class="seg other" style="height:{other_h}%"></div>'
            f'<div class="seg bad" style="height:{bad_h}%"></div>'
            f'<div class="seg ok" style="height:{ok_h}%"></div>'
            f"</div><small>{html.escape(bucket[6:8])}</small></div>"
        )

    ns_rows = []

    for namespace, item in sorted(
        by_namespace.items(), key=lambda kv: kv[1].get("total", 0), reverse=True
    ):
        ratio = item.get("success_ratio") or 0

        ns_rows.append(
            f'<tr><td><span class="tag">{html.escape(mask_name(namespace, 4))}</span></td>'
            f'<td class="num">{item.get("total", 0)}</td>'
            f'<td class="num">{item.get("success", 0)}</td>'
            f'<td class="num">{item.get("failed", 0)}</td>'
            f'<td class="num">{format_ratio(item.get("success_ratio"))}</td>'
            f'<td><div class="bar{" bad" if item.get("failed") else ""}">'
            f'<i style="width:{round(ratio * 100, 1)}%"></i></div></td></tr>'
        )

    flow_rows = []

    for item in top_flows:
        ratio = item.get("success_ratio") or 0

        flow_rows.append(
            f'<tr><td><span class="tag">{html.escape(mask_name(item.get("namespace"), 4))}</span></td>'
            f'<td class="mask">{html.escape(mask_name(item.get("flow_id"), 4))}</td>'
            f'<td class="num">{item.get("total", 0)}</td>'
            f'<td class="num">{item.get("success", 0)}</td>'
            f'<td class="num">{item.get("failed", 0)}</td>'
            f'<td class="num">{format_ratio(item.get("success_ratio"))}</td>'
            f'<td class="num">{html.escape(mask_time(item.get("last_run")))}</td></tr>'
        )

    ratio_pct = round((window.get("success_ratio") or 0) * 100, 1)

    template = (
        "<!doctype html><html lang=\"zh-Hant\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="refresh" content="300">'
        "<title>ETL Automation — The Engine of Intelligent Data Orchestration</title>"
        "<style>__CSS__</style></head><body>"
        "<header><div><h1><span></span>ETL Automation — The Engine of Intelligent Data Orchestration</h1>"
        "<p>生成時間 __GENERATED__ · 後端回應 __LATENCY__ ms · 資料窗口 __HOURS__ 小時</p></div>"
        "<div class=\"badge__BADGE__\"><b>__STATUS__</b> 網關與後端連通性</div></header>"
        "<main>"
        '<div class="cards">__CARDS__</div>'
        '<div class="grid2">'
        '<div class="panel pstate"><h2><i></i>狀態分布與摘要</h2><div class="summary">'
        '<div class="donut" style="--p:__RATIO__"><em>__RATIO__%<small>成功率</small></em></div>'
        '<dl class="kv">__KV__</dl></div>'
        '<div class="distbar">__DIST__</div><div class="legend">__DIST_LEGEND__</div></div>'
        '<div class="panel pchart"><h2><i></i>每小時執行趨勢</h2>'
        '<div class="chart">__BARS__</div>'
        '<div class="legend"><span><i style="background:#1fa971"></i>成功</span>'
        '<span><i style="background:#e5484d"></i>失敗</span>'
        '<span><i style="background:#aab6c8"></i>其它</span></div></div></div>'
        '<div class="grid2">'
        '<div class="panel"><h2><i></i>按命名空間</h2><div class="tablewrap"><table><thead><tr><th>命名空間</th>'
        '<th class="num">總數</th><th class="num">成功</th><th class="num">失敗</th>'
        '<th class="num">成功率</th><th>佔比</th></tr></thead><tbody>__NS_ROWS__</tbody></table></div></div>'
        '<div class="panel"><h2><i></i>Top Flows</h2><div class="tablewrap"><table><thead><tr><th>命名空間</th><th>Flow</th>'
        '<th class="num">總數</th><th class="num">成功</th><th class="num">失敗</th>'
        '<th class="num">成功率</th><th class="num">最後執行</th></tr></thead>'
        "<tbody>__FLOW_ROWS__</tbody></table></div></div></main>"
        "<footer>資料來自網關 /api/v2/health（JSON），頁面每 5 分鐘自動重新整理；"
        "命名空間、Flow 名稱與時間已遮罩處理，僅呈現彙總視圖。</footer>"
        "<script>__JS__</script></body></html>"
    )

    kv_items = [
        ("窗口內執行", window.get("total", 0)),
        ("累計執行", all_time.get("total", 0)),
        ("執行速率", f"{summary.get('rate_per_minute', 0)} 次/分"),
        ("活躍 Flow", summary.get("active_flows", 0)),
        ("平均耗時", format_duration(summary.get("avg_duration_s"))),
        ("P95 耗時", format_duration(summary.get("p95_duration_s"))),
        ("最長耗時", format_duration(summary.get("max_duration_s"))),
        ("後端狀態碼", backend.get("code", "-")),
    ]

    kv_html = "".join(
        f"<dt>{html.escape(str(label))}</dt><dd>{html.escape(str(value))}</dd>"
        for label, value in kv_items
    )

    page = (
        template.replace("__CSS__", DASHBOARD_CSS)
        .replace("__JS__", DASHBOARD_JS)
        .replace("__GENERATED__", html.escape(str(data.get("generated_at") or "")))
        .replace("__LATENCY__", html.escape(str(backend.get("latency_ms"))))
        .replace("__HOURS__", html.escape(str((data.get("window") or {}).get("hours", 24))))
        .replace("__BADGE__", "" if healthy else " bad")
        .replace("__STATUS__", status_text)
        .replace("__CARDS__", "".join(card_html))
        .replace("__RATIO__", f"{ratio_pct:.1f}")
        .replace("__KV__", kv_html)
        .replace("__DIST__", dist_bars)
        .replace("__DIST_LEGEND__", dist_legend)
        .replace("__BARS__", "".join(bars))
        .replace("__NS_ROWS__", "".join(ns_rows) or '<tr><td colspan="6">暫無資料</td></tr>')
        .replace("__FLOW_ROWS__", "".join(flow_rows) or '<tr><td colspan="7">暫無資料</td></tr>')
    )

    return page


@app.get("/api/v2/health")
async def health(request: Request):
    """网关自身 + 后端 Kestra 的健康检查与执行统计（浏览器返回仪表盘）"""

    backend = {"status": "ok"}

    started = time.perf_counter()

    try:
        response = await client.get(
            f"{BACKEND}/api/v1/namespaces/search",
            headers=backend_headers(),
            timeout=httpx.Timeout(5.0, connect=3.0),
        )
        backend["code"] = response.status_code

        if response.status_code != 200:
            backend["status"] = "error"

    except Exception as exc:
        backend["status"] = "error"
        backend["detail"] = type(exc).__name__

    backend["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)

    # 后端执行统计（带缓存）
    stats = {}

    try:
        stats = await collect_stats(STATS_WINDOW_HOURS, STATS_TOP)

        backend["window"] = stats["window"]
        backend["executions"] = stats["executions"]
        backend["by_namespace"] = stats["by_namespace"]
        backend["top_flows"] = stats["top_flows"]
        backend["hourly"] = stats["hourly"]
        backend["flows"] = stats["flow_inventory"]
        backend["summary"] = stats["summary"]

    except Exception as exc:
        backend.setdefault("detail", type(exc).__name__)

    healthy = backend["status"] == "ok"

    payload = {
        "status": "ok" if healthy else "degraded",
        "backend": backend,
    }

    output_format = (request.query_params.get("format") or "").lower()

    # 默认返回仪表盘 HTML，?format=json 返回 JSON
    wants_html = output_format != "json"

    if wants_html:
        page = render_dashboard(
            {
                **payload,
                "generated_at": stats.get("generated_at"),
                "window": stats.get("window"),
                "executions": stats.get("executions"),
                "by_namespace": stats.get("by_namespace"),
                "top_flows": stats.get("top_flows"),
                "hourly": stats.get("hourly"),
                "flow_inventory": stats.get("flow_inventory"),
                "summary": stats.get("summary"),
            }
        )

        return HTMLResponse(content=page, status_code=200 if healthy else 503)

    return JSONResponse(status_code=200 if healthy else 503, content=payload)


@app.api_route(
    f"{MCP_PREFIX}/{{target}}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@app.api_route(
    f"{MCP_PREFIX}/{{target}}/{{rest:path}}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def gateway(request: Request, target: str, rest: str = ""):

    ensure_tenant(request)

    # PDP：针对受保护账号进行 Cerbos 授权
    if target in PROTECTED_TARGETS:

        principal = authenticate(request)

        if principal is None:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={
                    "WWW-Authenticate": 'Basic realm="MCP Gateway"'
                },
            )

        if not await cerbos_allow(
            principal, target, "access", ip=client_ip(request)
        ):
            raise HTTPException(
                status_code=403,
                detail="Forbidden",
            )

    # 防止路径穿越
    if target in (".", "..") or "/" in target or "\\" in target:
        raise HTTPException(400, "Invalid target")

    # 组装后端 URL
    path = f"{BACKEND_MCP_PREFIX}/{target}"

    if rest:
        path += f"/{rest}"

    return await proxy_to_backend(request, path)


@app.api_route(
    "/api/v2/{rest:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def kestra_api(request: Request, rest: str):
    """Kestra 管理 API 代理：/api/v2/* -> 后端 /api/v1/*，按 Cerbos 策略授权"""

    ensure_tenant(request)

    principal = authenticate(request)

    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={
                "WWW-Authenticate": 'Basic realm="MCP Gateway"'
            },
        )

    action = API_ACTIONS.get(request.method.upper(), "read")

    body = await request.body()

    flow_id = extract_flow_id(request, rest, body)

    # flow 归属：flow id 需以 "<账号>_" 开头
    ensure_flow_owner(principal, flow_id)

    # 资源标识交给策略判定：具体 flow 用 flow/{flowId}，其余用 path/{路径}
    resource_id = f"flow/{flow_id}" if flow_id else f"path/{rest}"

    if not await cerbos_allow(
        principal, resource_id, action, kind="kestra-api", ip=client_ip(request)
    ):
        raise HTTPException(
            status_code=403,
            detail="Forbidden",
        )

    # 创建 flow 却无法确定 flow id 时按拒绝处理（fail closed）
    if request.method.upper() == "POST" and _targets_flows(rest) and not flow_id:
        raise HTTPException(
            status_code=403,
            detail="Flow id could not be determined",
        )

    return await proxy_to_backend(request, f"/api/v1/{rest}")
