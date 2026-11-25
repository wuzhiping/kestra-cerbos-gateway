import os
import base64
import secrets

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

BACKEND = os.getenv("BACKEND_URL", "http://10.17.1.201:38080")
MCP_PREFIX = "/api/v1/main/mcp"

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

# Kestra 租户（管理 API 需要）
KESTRA_TENANT = os.getenv("KESTRA_TENANT", "main")

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


async def cerbos_allow(
    principal_id: str,
    resource_id: str,
    action: str,
    kind: str = "kestra-mcp",
) -> bool:
    """调用 Cerbos PDP，判断 principal 是否有权对资源执行 action"""

    if not CERBOS_URL:
        return False

    payload = {
        "requestId": f"{principal_id}-{kind}-{resource_id}",
        "principal": {
            "id": principal_id,
            "roles": ["user"],
            "policyVersion": "default",
        },
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


async def proxy_to_backend(request: Request, path: str) -> StreamingResponse:
    """转发请求到 Kestra 后端，并注入后端 Basic Auth"""

    url = BACKEND + path

    if request.url.query:
        url += "?" + request.url.query

    # 覆盖客户端的 Authorization，使用后端原有认证
    headers = dict(request.headers)

    headers.pop("host", None)
    headers.pop("authorization", None)
    headers.pop("content-length", None)

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


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.api_route(
    "/api/v1/main/mcp/{target}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
@app.api_route(
    "/api/v1/main/mcp/{target}/{rest:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def gateway(request: Request, target: str, rest: str = ""):

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

        if not await cerbos_allow(principal, target, "access"):
            raise HTTPException(
                status_code=403,
                detail="Forbidden",
            )

    # 防止路径穿越
    if target in (".", "..") or "/" in target or "\\" in target:
        raise HTTPException(400, "Invalid target")

    # 组装后端 URL
    path = f"{MCP_PREFIX}/{target}"

    if rest:
        path += f"/{rest}"

    return await proxy_to_backend(request, path)


@app.api_route(
    "/api/v1/{rest:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def kestra_api(request: Request, rest: str):
    """Kestra 管理 API 代理：/api/v1/*，按 Cerbos 策略授权"""

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

    if not await cerbos_allow(principal, rest, action, kind="kestra-api"):
        raise HTTPException(
            status_code=403,
            detail="Forbidden",
        )

    return await proxy_to_backend(request, f"/api/v1/{rest}")
