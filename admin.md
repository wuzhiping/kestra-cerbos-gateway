# Kestra MCP PDP Gateway — 管理 API 使用说明

网关地址：`https://kestra.feg.cn`，所有接口前缀 `/api/v2`。

- 认证：网关 Basic Auth，**每个账号独立密码**
- 授权：网关会做策略判定与 flow 归属校验，未通过直接返回 4xx
- Kestra 原生 `/api/v1/*`（UI 使用）不经过本网关

---

## 1. 接口一览

| 接口 | 说明 |
|---|---|
| `GET /api/v2/health` | 健康检查，无需认证 |
| `ANY /api/v2/main/mcp/{账号}` | MCP 端点，`{账号}` 为 MCP Server 名（账号） |
| `ANY /api/v2/main/mcp/{账号}/{其余路径}` | MCP 附加路径 |
| `ANY /api/v2/{其余路径}` | Kestra 管理 API（flows / namespaces / executions 等） |

---

## 2. 认证

所有接口（除 `/api/v2/health`）都需要携带网关 Basic Auth：

```bash
curl -u 'u199013:w199013' https://kestra.feg.cn/api/v2/flows/main
```

- 账号密码由管理员分配（配置项 `GATEWAY_USERS`，格式 `账号:密码,账号:密码`）
- 未分配的账号、密码错误、缺少 `Authorization` 头 → `401 {"detail":"Unauthorized"}`

---

## 3. MCP 调用

```bash
GW=https://kestra.feg.cn/api/v2/main/mcp/u199013
AUTH='u199013:w199013'
JSON='Content-Type: application/json'
ACCEPT='Accept: application/json, text/event-stream'
```

**① initialize**（响应头会返回 `Mcp-Session-Id`，后续请求需带回）

```bash
curl -si -u "$AUTH" -X POST "$GW" -H "$JSON" -H "$ACCEPT" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1.0"}}}'
```

**② tools/list**

```bash
curl -s -u "$AUTH" -X POST "$GW" -H "$JSON" -H "$ACCEPT" \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

**③ tools/call**

```bash
curl -s -u "$AUTH" -X POST "$GW" -H "$JSON" -H "$ACCEPT" \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"oauth2_ip_dag_mcp","arguments":{}}}'
```

> 响应可能是普通 JSON，也可能是 SSE（`event: message` + `data: {...}`），客户端两种都要能解析。

---

## 4. 管理 API

基础路径：`BASE=https://kestra.feg.cn/api/v2`，示例账号 `u199013`。

### 4.1 查询

```bash
AUTH='u199013:w199013'; BASE=https://kestra.feg.cn/api/v2

curl -s -u "$AUTH" "$BASE/namespaces/search"                  # 命名空间列表
curl -s -u "$AUTH" "$BASE/flows/main"                          # 某命名空间的 flow 列表
curl -s -u "$AUTH" "$BASE/flows/search?sort=namespace:asc,id:asc&size=50"   # 全局搜索
curl -s -u "$AUTH" "$BASE/executions/search?size=10"           # 执行记录
```

> 搜索接口在本 Kestra 版本仅支持 `page` / `size` / `sort`；`q`、`namespace`、`ids` 等过滤参数不生效，需要精确过滤时请用 `/flows/{namespace}` 再在客户端筛选。

### 4.2 flow id 命名要求

通过网关**读 / 改 / 删某个具体 flow**，或**创建 flow** 时，flow id 必须以 `<账号>_` 开头：

| 账号 | 允许 | 拒绝（403） |
|---|---|---|
| `u199013` | `u199013_daily` | `u041007_daily`、`daily` |

命名空间级别的列表（`/flows/{namespace}`）与其它非 flow 接口不受此限制。

### 4.3 创建

```bash
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
```

> - 请求体必须为 `application/x-yaml`。
> - 该 Kestra 版本的 flow 文档**没有 `type` 字段**（流程默认 DAG），任务**不支持 `dependsOn`**，带上会返回 422。

### 4.4 读 / 改 / 删

```bash
curl -s -u "$AUTH" "$BASE/flows/main/u199013_daily"                     # 读
curl -s -u "$AUTH" -X PUT "$BASE/flows/main/u199013_daily" \
  -H 'Content-Type: application/x-yaml' --data-binary @/tmp/u199013_daily.yaml   # 改
curl -s -u "$AUTH" -X DELETE "$BASE/flows/main/u199013_daily"            # 删
```

---

## 5. 错误码

| 状态码 | 响应 | 原因 |
|---|---|---|
| 400 | `{"detail":"Tenant must be 'main'"}` | 请求里带了非 `main` 的租户（`X-Kestra-Tenant` 头或 `?tenant=`） |
| 401 | `{"detail":"Unauthorized"}` | 缺少/错误的 Basic Auth，或账号未分配 |
| 403 | `{"detail":"Forbidden"}` | 策略判定不通过（授权服务不可用时也会按拒绝处理） |
| 403 | `{"detail":"Flow id must be prefixed with '<账号>_'"}` | flow id 不属于当前账号 |
| 404 | `{"detail":"Not Found"}` | 网关没有该接口（例如 `/health`、`/api/v1/*`） |
| 其它 | Kestra 原始响应 | 上游返回的状态码与响应体原样返回 |

---

## 6. 配置项（管理员）

| 配置项 | 说明 |
|---|---|
| `GATEWAY_USERS` | 各账号密码，格式 `账号:密码,账号:密码`；未列出的账号无法登录 |
| `KESTRA_BASIC_AUTH` | 网关访问 Kestra 后端所用凭证（Base64 的 `账号:密码`） |
| `CERBOS_URL` | 授权服务地址 |

### 6.1 策略维护

策略文件在 `cerbos/policies/`，修改后用 Admin API 发布（立即生效，无需重启网关）：

```bash
CERBOS_URL=http://10.17.1.201:3592 \
CERBOS_ADMIN_USER=cerbos CERBOS_ADMIN_PASSWORD=cerbosAdmin \
python3 cerbos/deploy_policy.py                      # 发布全部策略
python3 cerbos/deploy_policy.py cerbos/policies/kestra-api.yaml   # 发布单个策略
```

| 用途 | 方法 | 路径 | 请求体 |
|---|---|---|---|
| 发布/更新策略 | `POST` | `{CERBOS_URL}/admin/policy` | `{"policies": [<策略文档>]}` |
| 策略列表 | `GET` | `{CERBOS_URL}/admin/policies` | — |
| 读取单个策略 | `GET` | `{CERBOS_URL}/admin/policy?id=<策略ID>` | — |

> 策略 ID 形如 `resource.kestra_api.vdefault`（前缀为 `resource.` + 资源名 + `.v` + 版本）。

### 6.2 部署

```bash
git pull && docker compose up -d --build
docker compose ps      # 健康检查走 /api/v2/health
```
