# Kestra MCP 网关 — 管理 API 使用说明

网关地址：`https://kestra.feg.cn`，所有接口前缀 `/api/v2`。

- 认证：网关 Basic Auth，**每个账号独立密码**
- 授权：网关会做访问授权与 flow 归属校验，未通过直接返回 4xx
- Kestra 原生 `/api/v1/*`（UI 使用）不经过本网关

---

## 1. 接口一览

| 接口 | 说明 |
|---|---|
| `GET /api/v2/health` | 健康检查：浏览器返回运行状态仪表盘，脚本返回 JSON（含后端连通性与执行统计） |
| `ANY /api/v2/main/mcp/{账号}` | MCP 端点，`{账号}` 为 MCP Server 名（账号） |
| `ANY /api/v2/main/mcp/{账号}/{其余路径}` | MCP 附加路径 |
| `ANY /api/v2/{其余路径}` | Kestra 管理 API（flows / namespaces / executions 等） |

---

## 2. 认证

所有接口（除 `/api/v2/health`）都需要携带网关 Basic Auth：

```bash
curl -u 'u199013:w199013' https://kestra.feg.cn/api/v2/flows/main
```

- 账号密码由管理员分配（`GATEWAY_USERS`，格式 `账号:密码,账号:密码`）
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

## 5. 健康检查（含后端执行统计）

浏览器直接打开 `https://kestra.feg.cn/api/v2/health` 会看到一个运行状态仪表盘（24 小时执行数、成功率、失败/进行中/待处理、每小时趋势、按命名空间与 Top Flows 表格，每 30 秒自动刷新）；脚本 / curl 访问同一路径则返回 JSON。

```bash
curl -s https://kestra.feg.cn/api/v2/health
```

```json
{
  "status": "ok",
  "backend": {
    "status": "ok",
    "code": 200,
    "latency_ms": 12.4,
    "window": {"hours": 24, "from": "...", "to": "..."},
    "executions": {
      "window":   {"total": 2227, "success": 2222, "failed": 1, "running": 0, "pending": 0, "paused": 0, "other": 4, "finished": 2223, "success_ratio": 0.9996},
      "all_time": {"total": 4809, "success": 4796, "failed": 6, "running": 0, "pending": 0, "paused": 0, "other": 7, "finished": 4802, "success_ratio": 0.9988},
      "all_time_total": 4809
    },
    "by_namespace": {"main": {"total": 1982, "success": 1969, "failed": 6, "success_ratio": 0.997}},
    "top_flows": [{"namespace": "main", "flow_id": "oauth2_ip_dag", "total": 1814, "success": 1814, "failed": 0, "success_ratio": 1.0, "last_run": "..."}],
    "hourly": {"11-25 23:00": {"total": 15, "success": 15, "failed": 0, "success_ratio": 1.0}}
  }
}
```

- 后端不可达时返回 HTTP 503，`status` 变为 `degraded`，并带 `detail`（异常类型）
- 状态口径：`success` = SUCCESS，`failed` = FAILED，`running` = RUNNING（进行中），`pending` = CREATED（待处理），`paused` = PAUSED；`success_ratio` = success / (success + failed)
- 统计默认取过去 24 小时（`window.hours`），结果缓存 30 秒

---

## 6. 错误码

| 状态码 | 响应 | 原因 |
|---|---|---|
| 400 | `{"detail":"Tenant must be 'main'"}` | 请求里带了非 `main` 的租户（`X-Kestra-Tenant` 头或 `?tenant=`） |
| 401 | `{"detail":"Unauthorized"}` | 缺少/错误的 Basic Auth，或账号未分配 |
| 403 | `{"detail":"Forbidden"}` | 无权访问该资源 |
| 403 | `{"detail":"Flow id must be prefixed with '<账号>_'"}` | flow id 不属于当前账号 |
| 404 | `{"detail":"Not Found"}` | 网关没有该接口（例如 `/health`、`/api/v1/*`） |
| 其它 | Kestra 原始响应 | 上游返回的状态码与响应体原样返回 |
