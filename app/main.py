import os
import base64
import secrets

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

BACKEND = "http://10.17.1.201:38080"
MCP_PREFIX = "/api/v1/main/mcp"

# 原有后端 Basic Auth
BACKEND_AUTH = os.getenv("KESTRA_BASIC_AUTH", "")

# 新的 Gateway Basic Auth
GATEWAY_USER = os.getenv("GATEWAY_USER", "u041007")
GATEWAY_PASSWORD = os.getenv("GATEWAY_PASSWORD", "")

PROTECTED_TARGET = "u041007"

app = FastAPI(title="MCP PDP Gateway")

client = httpx.AsyncClient(
    timeout=httpx.Timeout(300, connect=15),
)


@app.on_event("shutdown")
async def shutdown():
    await client.aclose()


def authenticate(request: Request):
    auth = request.headers.get("Authorization", "")

    if not auth.startswith("Basic "):
        return False

    try:
        decoded = base64.b64decode(
            auth[6:], validate=True
        ).decode()

        username, password = decoded.split(":", 1)

    except Exception:
        return False

    return (
        secrets.compare_digest(username, GATEWAY_USER)
        and secrets.compare_digest(password, GATEWAY_PASSWORD)
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

    # PDP：针对 u041007 进行额外授权
    if target == PROTECTED_TARGET:

        if not authenticate(request):
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={
                    "WWW-Authenticate": 'Basic realm="MCP Gateway"'
                },
            )

    # 防止路径穿越
    if target in (".", "..") or "/" in target or "\\" in target:
        raise HTTPException(400, "Invalid target")

    # 组装后端 URL
    path = f"{MCP_PREFIX}/{target}"

    if rest:
        path += f"/{rest}"

    url = BACKEND + path

    if request.url.query:
        url += "?" + request.url.query

    # 覆盖客户端的 Authorization，使用后端原有认证
    headers = dict(request.headers)

    headers.pop("host", None)
    headers.pop("authorization", None)

    if BACKEND_AUTH:
        headers["Authorization"] = (
            "Basic " + BACKEND_AUTH
        )

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