# Kestra MCP PDP Gateway — 管理 API 文档

面向自动化客户端（Agent / MCP 客户端 / 运维脚本）的网关接口说明。

- 网关地址：`https://kestra.feg.cn`
- 网关对外接口前缀：`/api/v2`
- 鉴权模型：**网关 Basic Auth（每账号独立密码） → Cerbos PDP 策略判定 → 后端凭证注入 → Kestra**
- Kestra 原生 `/api/v1/*`（UI 使用）**不经过本网关、不做 PDP 管控**

---

## 1. 架构与请求链路

```
客户端 --Basic Auth(账号:密码)--> 网关 /api/v2/*
                                    │  1. 校验网关 Basic Auth（账号独立密码）
                                    │  2. 租户校验（写死 main）
                                    │  3. Cerbos PDP 授权（fail closed）
                                    │  4. flow 归属校验（<账号>_ 前缀）
                                    ▼
                          注入 KESTRA_BASIC_AUTH + X-Kestra-Tenant: main
                                    ▼
                        Kestra 后端 /api/v1/*（MCP 与管理 API）
```

| 组件 | 地址 / 来源 | 说明 |
|---|---|---|
| 网关 | `https://kestra.feg.cn`（容器端口 8080） | FastAPI + httpx，流式透传 |
| Cerbos PDP | `http://10.17.1.201:3592` | 策略决策点，`/api/check/resources` |
| Kestra 后端 | `http://10.17.1.201:38080` | 由网关注入后端 Basic Auth |
| Cerbos Admin API | `http://10.17.1.201:3592/admin/*` | 策略发布（`cerbos/deploy_policy.py`） |

---

## 2. 接口清单

| 网关路径 | 后端路径 | 说明 | 鉴权 |
|---|---|---|---|
| `GET /api/v2/health` | — | 健康检查（无需认证） | 无 |
| `ANY /api/v2/main/mcp/{target}` | `/api/v1/main/mcp/{target}` | Kestra MCP 端点，`target` = MCP Server 名（账号） | 受保护账号：Basic Auth + Cerbos `kestra-mcp/access` |
| `ANY /api/v2/main/mcp/{target}/{rest}` | `/api/v1/main/mcp/{target}/{rest}` | MCP 附加路径 | 同上 |
| `ANY /api/v2/{rest}` | `/api/v1/{rest}` | Kestra 管理 API 代理（flows / namespaces / executions / …） | Basic Auth + Cerbos `kestra-api/{read,create,update,delete}` |

> `/health`、`/api/v1/*` 在网关上**不存在**（404）；`/api/v1/*` 由反向代理直接给 Kestra UI 使用，不经 PDP。

---

## 3. 认证

请求必须携带网关 Basic Auth，密码为**每账号独立**：

```bash
curl -u 'u199013:w199013' https://kestra.feg.cn/api/v2/flows/main
```

- 账号密码来自 `compose.yaml` 的 `GATEWAY_USERS`：`账号:密码,账号:密码`
- 未配置的账号、密码错误、缺失 Authorization 头 → `401 {"detail":"Unauthorized"}`（响应头 `WWW-Authenticate: Basic realm="MCP Gateway"`）
- 账号密码中不能包含 `,` 或 `:`（解析分隔符）
- 网关不校验客户端携带的 `Authorization` 是否为后端凭证：转发时一律覆盖为 `KESTRA_BASIC_AUTH`

---

## 4. 授权（Cerbos PDP）

网关调用 `POST {CERBOS_URL}/api/check/resources`，principal 固定 `roles=["user"]`、`policyVersion="default"`：

| 场景 | 资源 kind | 资源 id | action |
|---|---|---|---|
| MCP 访问受保护账号 | `kestra-mcp` | `{target}`（账号） | `access` |
| 管理 API | `kestra-api` | 请求路径（去掉 `/api/v2/` 前缀），如 `flows/main/u199013_x` | 由 HTTP 方法映射 |

方法 → action 映射：`GET/HEAD/OPTIONS → read`，`POST → create`，`PUT/PATCH → update`，`DELETE → delete`。

- Cerbos 不可用 / 超时 / 返回异常 → **fail closed**（按拒绝处理，`403`）
- 策略文件：`cerbos/policies/kestra-mcp.yaml`、`cerbos/policies/kestra-api.yaml`
- `kestra-api` 已放开到所有通过网关认证的账号（`roles=["user"]`），账号白名单与 flow 归属由代码控制（见 §3、§6）

### 4.1 发布策略（Cerbos Admin API）

```bash
CERBOS_URL=http://10.17.1.201:3592 \
CERBOS_ADMIN_USER=cerbos CERBOS_ADMIN_PASSWORD=cerbosAdmin \
python3 cerbos/deploy_policy.py            # 发布 cerbos/policies/ 下全部策略
python3 cerbos/deploy_policy.py cerbos/policies/kestra-api.yaml   # 发布单个策略
```

Admin API 细节（Cerbos 0.57）：

| 用途 | 方法 | 路径 | 请求体 |
|---|---|---|---|
| 发布/更新策略 | `POST` | `/admin/policy` | `{"policies": [<策略文档>]}` |
| 策略列表 | `GET` | `/admin/policies` | — |
| 读取单个策略 | `GET` | `/admin/policy?id=resource.kestra_api.vdefault` | — |

策略文档格式（一个文件一个资源名）：

```yaml
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: kestra-api
  rules:
    # 管理 API 的准入交给代码控制（账号白名单 + flow 归属），这里放开到所有已认证账号
    - actions: ["read", "create", "update", "delete"]
      effect: EFFECT_ALLOW
      roles: ["user"]
```

> `kestra-api` 策略不再限制 principal 名单：可访问的账号由网关 Basic Auth（`GATEWAY_USERS` 白名单，未配置账号 → 401）与 flow 归属规则（`<账号>_` 前缀 → 403）共同约束。
> `kestra-mcp` 策略仍保留 `request.principal.id == request.resource.id`（MCP 仅可访问本人资源）。

> 旧路径 `/adminapi/policy` 在该实例不可用（返回 `Admin service is disabled by the configuration`），必须使用 `/admin/policy`。

---

## 5. 租户

- 租户写死为 `main`（Kestra OSS 单租户），代码常量 `KESTRA_TENANT = "main"`
- 客户端通过 `X-Kestra-Tenant` 头或 `?tenant=` 指定其它租户 → `400 {"detail":"Tenant must be 'main'"}`
- 转发时网关会**剥离**客户端的 `tenant` 查询参数与 `X-Kestra-Tenant` 头，统一注入 `X-Kestra-Tenant: main`

---

## 6. flow 归属规则

通过网关**控制（read / create / update / delete）某个具体 flow** 时，flow id 必须以 `<账号>_` 开头：

- 路径形式 `flows/{namespace}/{flowId}` → 取 `{flowId}`
- 创建 `POST /api/v2/flows` → flow id 在请求体里（YAML 顶层 `id:`，或 JSON `id` / `flow.id`）
- `flows/{namespace}`（命名空间列表）、其它非 flow 路径 → 不涉及具体 flow，不受此限制
- 不满足前缀 → `403 {"detail":"Flow id must be prefixed with '<账号>_'"}`

示例（账号 `u199013`）：

| 请求 | 结果 |
|---|---|
| 创建 `u199013_daily` | 200 |
| 创建 `u041007_daily` | 403 |
| 读 / 改 / 删 `u199013_daily` | 200 / 200 / 204 |
| 读 / 改 / 删 `u041007_daily` | 403 |
| 读无前缀的历史 flow（如 `oauth2_ip_dag`） | 403 |

> 存量 flow 若不带账号前缀，将无法经网关读写；如需接管，请先改名（改名会连带影响 MCP 工具名与定时任务）。

---

## 7. 错误码

| 状态码 | 响应体 | 触发条件 |
|---|---|---|
| 400 | `{"detail":"Tenant must be 'main'"}` | 请求租户与 `main` 不一致 |
| 400 | `{"detail":"Invalid target"}` | MCP target 含路径穿越字符 |
| 401 | `{"detail":"Unauthorized"}` | 缺失/错误 Basic Auth、账号未配置 |
| 403 | `{"detail":"Forbidden"}` | Cerbos 判定不允许 / Cerbos 不可用（fail closed） |
| 403 | `{"detail":"Flow id must be prefixed with '<账号>_'"}` | flow 归属校验失败 |
| 404 | `{"detail":"Not Found"}` | 网关无该路由（如 `/health`、`/api/v1/*`） |
| 2xx/4xx/5xx | Kestra 原始响应 | 上游 Kestra 的状态码与响应体原样透传 |

---

## 8. 使用示例

### 8.1 健康检查

```bash
curl -s https://kestra.feg.cn/api/v2/health
# {"status":"ok"}
```

### 8.2 MCP：列工具 / 调工具

```bash
GW=https://kestra.feg.cn/api/v2/main/mcp/u199013

# initialize（响应头带 Mcp-Session-Id，后续请求需带上）
curl -si -u 'u199013:w199013' -X POST "$GW" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1.0"}}}'

# tools/list（带上次返回的 Mcp-Session-Id）
curl -s -u 'u199013:w199013' -X POST "$GW" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# tools/call
curl -s -u 'u199013:w199013' -X POST "$GW" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"oauth2_ip_dag_mcp","arguments":{}}}'
```

### 8.3 管理 API

```bash
AUTH='u199013:w199013'
BASE=https://kestra.feg.cn/api/v2

# 命名空间列表
curl -s -u "$AUTH" "$BASE/namespaces/search"

# 某命名空间的 flow 列表
curl -s -u "$AUTH" "$BASE/flows/main"

# 全局搜索（该 Kestra 版本仅支持 page / size / sort，q、namespace 等过滤参数不生效）
curl -s -u "$AUTH" "$BASE/flows/search?sort=namespace:asc,id:asc&size=50"

# 创建 flow（id 必须带账号前缀；请求体 Content-Type 为 application/x-yaml）
cat > /tmp/u199013_daily.yaml <<'YAML'
id: u199013_daily
namespace: main
description: 每分钟 POST https://abc.feg.com.tw/oauth2/ip
tasks:
  - id: post_oauth2_ip
    type: io.kestra.plugin.core.http.Request
    uri: https://abc.feg.com.tw/oauth2/ip
    method: POST
    body: "{}"
triggers:
  - id: every_minute
    type: io.kestra.plugin.core.trigger.Schedule
    cron: "* * * * *"
    timezone: Asia/Shanghai
YAML
curl -s -u "$AUTH" -X POST "$BASE/flows" \
  -H 'Content-Type: application/x-yaml' --data-binary @/tmp/u199013_daily.yaml

# 读 / 改 / 删
curl -s -u "$AUTH" "$BASE/flows/main/u199013_daily"
curl -s -u "$AUTH" -X PUT "$BASE/flows/main/u199013_daily" \
  -H 'Content-Type: application/x-yaml' --data-binary @/tmp/u199013_daily.yaml
curl -s -u "$AUTH" -X DELETE "$BASE/flows/main/u199013_daily"
```

> Kestra 侧提示：创建 flow 只接受 `application/x-yaml`；该实例的 flow 模型**无 `type` 字段**（0.24+ 全部流程默认 DAG），且任务**不支持 `dependsOn`**——带上会返回 422。

---

## 9. 环境变量

`compose.yaml`（服务名 `kestra-mcp`，容器端口 8080）：

| 变量 | 值 | 说明 |
|---|---|---|
| `BACKEND_URL` | `http://10.17.1.201:38080` | Kestra 后端 |
| `KESTRA_BASIC_AUTH` | Base64(`账号:密码`) | 网关转发时注入的后端凭证 |
| `GATEWAY_USER` | `u041007` | 默认账号（客户端 Basic 用户名为空时使用） |
| `GATEWAY_USERS` | `u041007:w041007,u199013:w199013` | 各账号独立密码 |
| `CERBOS_URL` | `http://10.17.1.201:3592` | Cerbos PDP |
| `CERBOS_ADMIN_USER` / `CERBOS_ADMIN_PASSWORD` | `cerbos` / `cerbosAdmin` | 发布策略用的 Admin API 账号 |

代码内固定值：`KESTRA_TENANT = "main"`、`PROTECTED_TARGETS = {u041007, u199013}`、`MCP_PREFIX = /api/v2/main/mcp`。

---

## 10. 部署与运维

```bash
git pull && docker compose up -d --build
docker compose ps                 # 健康检查：/api/v2/health
docker compose logs -f kestra-mcp
```

策略变更后：

```bash
python3 cerbos/deploy_policy.py   # 通过 Cerbos Admin API 立即生效，无需重启
```

---

## 11. 目录结构

```
app/main.py                     网关实现（认证 / PDP / 租户 / flow 归属 / 代理）
cerbos/policies/kestra-mcp.yaml MCP 访问策略
cerbos/policies/kestra-api.yaml 管理 API 策略
cerbos/deploy_policy.py         策略发布脚本（Cerbos Admin API）
compose.yaml                    服务编排与变量
admin.md                        本文档
```
