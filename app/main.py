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

    if not parts or parts[0] != "flows":
        return None

    # flows/{namespace}/{flowId}[/...]
    if len(parts) >= 3:
        return parts[2]

    # flows/{namespace}：命名空间级别的列表，不涉及单个 flow
    if len(parts) == 2:
        return None

    # POST flows：flow id 在请求体里
    return flow_id_from_body(request, body)


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

    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)

    all_states = Counter()
    window_states = Counter()
    by_namespace = defaultdict(Counter)
    by_flow = defaultdict(Counter)
    last_run = {}
    hourly = defaultdict(Counter)

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

        if started_at.isoformat() > last_run.get(key, ""):
            last_run[key] = started_at.isoformat()

        if started_at >= cutoff:
            window_states[current] += 1
            hourly[started_at.strftime("%m-%d %H:00")][current] += 1

    flow_stats = []

    for (namespace, flow_id), states in by_flow.items():
        item = summarize(states)
        item["namespace"] = namespace
        item["flow_id"] = flow_id
        item["last_run"] = last_run.get((namespace, flow_id))
        flow_stats.append(item)

    flow_stats.sort(key=lambda item: (item["total"], item["last_run"] or ""), reverse=True)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {
            "hours": window_hours,
            "from": cutoff.isoformat(),
            "to": datetime.now(timezone.utc).isoformat(),
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
        "fetch": fetched_at,
    }


DASHBOARD_CSS = """
*{box-sizing:border-box;scrollbar-width:thin}
body{margin:0;background:#f3f5f9;color:#172033;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{position:sticky;top:0;z-index:30;background:linear-gradient(100deg,#0e2340 0%,#1a3a6d 58%,#24518f 100%);color:#fff;padding:14px max(20px,calc((100vw - 1450px)/2));box-shadow:0 3px 14px rgba(14,35,64,.32);border-bottom:3px solid #3f8fe0;display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap}
header h1{margin:0;font-size:23px;letter-spacing:.3px}
header p{color:#bcd0ea;margin:4px 0 0;font-size:13px}
.badge{display:inline-flex;align-items:center;gap:7px;padding:7px 16px;border:1px solid rgba(255,255,255,.32);border-radius:20px;background:rgba(255,255,255,.12);color:#dbe7f7;font-size:12.5px;letter-spacing:.3px;white-space:nowrap}
.badge b{color:#fff;font-weight:700;letter-spacing:.6px}
.badge.bad b{color:#ffd7d7}
main{max-width:1450px;margin:22px auto;padding:0 18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card,.panel{background:#fff;border:1px solid #e3e8f0;border-radius:11px;padding:15px}
.card small{display:block;color:#68758b}
.card strong{display:block;font-size:26px;margin-top:4px}
.card small.sub{margin-top:4px;font-size:11px;color:#7b879b}
.card.ok{background:#e9f7ee;border-color:#b6e0c4;color:#14653a}
.card.ok small{color:#1b7c4a}
.card.bad{background:#fdeaea;border-color:#f0b6bb;color:#8d1b2c}
.card.bad small{color:#a3243a}
.card.warn{background:#fff7df;border-color:#f0dfa4;color:#7a5600}
.card.warn small{color:#93701a}
.panel{margin-top:16px}
.panel h2{margin:0 0 10px;font-size:16px;color:#2b3a55}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px}
.grid2 .panel{margin-top:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #eef1f6;white-space:nowrap}
th{color:#68758b;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.bar{height:7px;border-radius:4px;background:#eef1f6;overflow:hidden;min-width:90px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,#2f9e6b,#57c08c)}
.bar.bad i{background:linear-gradient(90deg,#c9433f,#e07672)}
.chart{display:flex;align-items:flex-end;gap:4px;height:150px;padding:8px 2px 0}
.chart .col{flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:3px;height:100%}
.chart .stack{width:100%;display:flex;flex-direction:column;justify-content:flex-end;height:100%}
.chart .seg{width:100%}
.chart .seg.ok{background:linear-gradient(180deg,#57c08c,#2f9e6b)}
.chart .seg.bad{background:linear-gradient(180deg,#e07672,#c9433f)}
.chart .seg.other{background:#c8cfdb}
.chart small{font-size:10px;color:#8b96a8;white-space:nowrap;transform:rotate(-35deg);transform-origin:right center;height:14px}
.legend{display:flex;gap:16px;font-size:12px;color:#68758b;margin-top:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
footer{max-width:1450px;margin:18px auto 30px;padding:0 18px;color:#8b96a8;font-size:12px}
"""


def format_ratio(value):
    return "-" if value is None else f"{value * 100:.2f}%"


def render_dashboard(data):
    """渲染运行状态仪表盘（纯 HTML/CSS，无外部依赖）"""

    backend = data.get("backend") or {}
    executions = data.get("executions") or {}
    window = executions.get("window") or {}
    all_time = executions.get("all_time") or {}
    by_namespace = data.get("by_namespace") or {}
    top_flows = data.get("top_flows") or []
    hourly = data.get("hourly") or {}
    inventory = data.get("flow_inventory") or {}

    healthy = data.get("status") == "ok"
    status_text = "正常" if healthy else "降级"

    cards = [
        ("24 小时执行", str(window.get("total", 0)), "窗口内执行总数"),
        ("成功率", format_ratio(window.get("success_ratio")), "success / (success + failed)"),
        ("失败", str(window.get("failed", 0)), "FAILED"),
        ("进行中", str(window.get("running", 0)), "RUNNING"),
        ("待处理", str(window.get("pending", 0)), "CREATED"),
        ("已暂停", str(window.get("paused", 0)), "PAUSED"),
        ("累计执行", str(all_time.get("total", 0)), "全部历史"),
        ("Flow 数", str(inventory.get("total") or 0), "命名空间内 flow 总量"),
    ]

    card_html = "".join(
        f'<div class="card"><small>{html.escape(title)}</small>'
        f"<strong>{html.escape(value)}</strong>"
        f'<small class="sub">{html.escape(sub)}</small></div>'
        for title, value, sub in cards
    )

    peak = max([item.get("total", 0) for item in hourly.values()] or [1]) or 1

    bars = []

    for bucket, item in hourly.items():
        total = item.get("total", 0) or 1
        ok_h = round(item.get("success", 0) / total * 100, 1)
        bad_h = round(item.get("failed", 0) / total * 100, 1)
        other_h = max(0.0, 100 - ok_h - bad_h)
        height = max(3, round(item.get("total", 0) / peak * 100, 1))

        bars.append(
            f'<div class="col" title="{html.escape(bucket)} 成功 {item.get("success", 0)}'
            f' 失败 {item.get("failed", 0)}">'
            f'<div class="stack" style="height:{height}%">'
            f'<div class="seg other" style="height:{other_h}%"></div>'
            f'<div class="seg bad" style="height:{bad_h}%"></div>'
            f'<div class="seg ok" style="height:{ok_h}%"></div>'
            f"</div><small>{html.escape(bucket[6:])}</small></div>"
        )

    ns_rows = []

    for namespace, item in sorted(by_namespace.items(), key=lambda kv: kv[1].get("total", 0), reverse=True):
        ratio = item.get("success_ratio") or 0
        ns_rows.append(
            f"<tr><td>{html.escape(str(namespace))}</td>"
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
            f"<tr><td>{html.escape(str(item.get('namespace')))}</td>"
            f"<td>{html.escape(str(item.get('flow_id')))}</td>"
            f'<td class="num">{item.get("total", 0)}</td>'
            f'<td class="num">{item.get("success", 0)}</td>'
            f'<td class="num">{item.get("failed", 0)}</td>'
            f'<td class="num">{format_ratio(item.get("success_ratio"))}</td>'
            f'<td class="num">{html.escape(str(item.get("last_run") or "-"))}</td></tr>'
        )

    template = (
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="refresh" content="30">'
        "<title>Kestra MCP 网关 · 运行状态</title><style>__CSS__</style></head><body>"
        "<header><div><h1>Kestra MCP 网关 · 运行状态</h1>"
        "<p>生成时间 __GENERATED__ · 后端响应 __LATENCY__ ms</p></div>"
        "<div class=\"badge__BADGE__\"><b>__STATUS__</b> 网关与后端连通性</div></header>"
        "<main>"
        '<div class="cards">__CARDS__</div>'
        '<div class="panel"><h2>每小时执行趋势（近 __HOURS__ 小时）</h2>'
        '<div class="chart">__BARS__</div>'
        '<div class="legend"><span><i style="background:#2f9e6b"></i>成功</span>'
        '<span><i style="background:#c9433f"></i>失败</span>'
        '<span><i style="background:#c8cfdb"></i>其它</span></div></div>'
        '<div class="grid2">'
        '<div class="panel"><h2>按命名空间</h2><table><thead><tr><th>命名空间</th>'
        '<th class="num">总数</th><th class="num">成功</th><th class="num">失败</th>'
        '<th class="num">成功率</th><th>占比</th></tr></thead><tbody>__NS_ROWS__</tbody></table></div>'
        '<div class="panel"><h2>Top Flows</h2><table><thead><tr><th>命名空间</th><th>Flow</th>'
        '<th class="num">总数</th><th class="num">成功</th><th class="num">失败</th>'
        '<th class="num">成功率</th><th class="num">最后运行</th></tr></thead>'
        "<tbody>__FLOW_ROWS__</tbody></table></div></div></main>"
        "<footer>数据来自网关 /api/v2/health（JSON），页面每 30 秒自动刷新。</footer>"
        "</body></html>"
    )

    page = (
        template.replace("__CSS__", DASHBOARD_CSS)
        .replace("__GENERATED__", html.escape(str(data.get("generated_at") or "")))
        .replace("__LATENCY__", html.escape(str(backend.get("latency_ms"))))
        .replace("__BADGE__", "" if healthy else " bad")
        .replace("__STATUS__", status_text)
        .replace("__CARDS__", card_html)
        .replace("__HOURS__", html.escape(str((data.get("window") or {}).get("hours", 24))))
        .replace("__BARS__", "".join(bars))
        .replace("__NS_ROWS__", "".join(ns_rows) or '<tr><td colspan="6">暂无数据</td></tr>')
        .replace("__FLOW_ROWS__", "".join(flow_rows) or '<tr><td colspan="7">暂无数据</td></tr>')
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

    except Exception as exc:
        backend.setdefault("detail", type(exc).__name__)

    healthy = backend["status"] == "ok"

    payload = {
        "status": "ok" if healthy else "degraded",
        "backend": backend,
    }

    accept = request.headers.get("accept", "")

    if "text/html" in accept and "application/json" not in accept:
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

    if not await cerbos_allow(
        principal, rest, action, kind="kestra-api", ip=client_ip(request)
    ):
        raise HTTPException(
            status_code=403,
            detail="Forbidden",
        )

    # flow 必须属于本人：flow id 需以 "<账号>_" 开头
    body = await request.body()

    ensure_flow_owner(principal, extract_flow_id(request, rest, body))

    return await proxy_to_backend(request, f"/api/v1/{rest}")
