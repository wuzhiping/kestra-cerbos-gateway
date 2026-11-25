import os
import base64
import json
import re
import secrets
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
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
        executions, total, fetched_at = _stats_cache["data"]

    else:
        started = time.perf_counter()
        executions, total = await fetch_executions()
        fetched_at = {
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "records": len(executions),
        }
        _stats_cache["at"] = now
        _stats_cache["data"] = (executions, total, fetched_at)

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

    flows = []

    for (namespace, flow_id), states in by_flow.items():
        item = summarize(states)
        item["namespace"] = namespace
        item["flow_id"] = flow_id
        item["last_run"] = last_run.get((namespace, flow_id))
        flows.append(item)

    flows.sort(key=lambda item: (item["total"], item["last_run"] or ""), reverse=True)

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
        "top_flows": flows[:top],
        "hourly": {
            bucket: summarize(states) for bucket, states in sorted(hourly.items())
        },
        "fetch": fetched_at,
    }


@app.get("/api/v2/admin/stats")
async def admin_stats(request: Request):
    """管理统计：执行成功率、进行中、待处理等"""

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
        principal, "admin/stats", "read", kind="kestra-api", ip=client_ip(request)
    ):
        raise HTTPException(
            status_code=403,
            detail="Forbidden",
        )

    try:
        hours = int(request.query_params.get("hours", "24"))
    except Exception:
        hours = 24

    try:
        top = int(request.query_params.get("top", "10"))
    except Exception:
        top = 10

    hours = max(1, min(hours, 24 * 30))
    top = max(1, min(top, 50))

    try:
        return await collect_stats(hours, top)

    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Backend unavailable",
        )


@app.get("/api/v2/health")
async def health():
    """网关自身 + 后端 Kestra 的健康检查"""

    backend = {"status": "ok", "url": BACKEND}

    started = time.perf_counter()

    headers = {"X-Kestra-Tenant": KESTRA_TENANT}

    if BACKEND_AUTH:
        headers["Authorization"] = "Basic " + BACKEND_AUTH

    try:
        response = await client.get(
            f"{BACKEND}/api/v1/namespaces/search",
            headers=headers,
            timeout=httpx.Timeout(5.0, connect=3.0),
        )
        backend["code"] = response.status_code

        if response.status_code != 200:
            backend["status"] = "error"

    except Exception as exc:
        backend["status"] = "error"
        backend["detail"] = type(exc).__name__

    backend["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)

    healthy = backend["status"] == "ok"

    return JSONResponse(
        status_code=200 if healthy else 503,
        content={
            "status": "ok" if healthy else "degraded",
            "backend": backend,
        },
    )


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
