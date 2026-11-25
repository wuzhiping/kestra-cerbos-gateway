# Kestra MCP 網關 — 管理 API 使用說明

網關位址：`https://kestra.feg.cn`，所有介面前綴 `/api/v2`。

- 認證：網關 Basic Auth，**每個帳號獨立密碼**
- 授權：網關會做存取授權與 flow 歸屬檢核，未通過直接回傳 4xx
- Kestra 原生 `/api/v1/*`（UI 使用）不經過本網關

---

## 1. 介面一覽

| 介面 | 說明 |
|---|---|
| `GET /api/v2/health` | 健康檢查：瀏覽器回傳執行狀態儀表板，腳本回傳 JSON（含後端連通性與執行統計） |
| `ANY /api/v2/main/mcp/{帳號}` | MCP 端點，`{帳號}` 為 MCP Server 名（帳號） |
| `ANY /api/v2/main/mcp/{帳號}/{其餘路徑}` | MCP 附加路徑 |
| `ANY /api/v2/{其餘路徑}` | Kestra 管理 API（flows / namespaces / executions 等） |

---

## 2. 認證

所有介面（除 `/api/v2/health`）都需要攜帶網關 Basic Auth：

```bash
curl -u 'u199013:w199013' https://kestra.feg.cn/api/v2/flows/main
```

- 帳號密碼由管理員配發（`GATEWAY_USERS`，格式 `帳號:密碼,帳號:密碼`）
- 未配發的帳號、密碼錯誤、缺少 `Authorization` 標頭 → `401 {"detail":"Unauthorized"}`

---

## 3. MCP 呼叫

```bash
GW=https://kestra.feg.cn/api/v2/main/mcp/u199013
AUTH='u199013:w199013'
JSON='Content-Type: application/json'
ACCEPT='Accept: application/json, text/event-stream'
```

**① initialize**（回應標頭會帶回 `Mcp-Session-Id`，後續請求需帶上）

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

> 回應可能是普通 JSON，也可能是 SSE（`event: message` + `data: {...}`），用戶端兩種都要能解析。

---

## 4. 管理 API

基礎路徑：`BASE=https://kestra.feg.cn/api/v2`，範例帳號 `u199013`。

### 4.1 查詢

```bash
AUTH='u199013:w199013'; BASE=https://kestra.feg.cn/api/v2

curl -s -u "$AUTH" "$BASE/namespaces/search"                  # 命名空間清單
curl -s -u "$AUTH" "$BASE/flows/main"                          # 某命名空間的 flow 清單
curl -s -u "$AUTH" "$BASE/flows/search?sort=namespace:asc,id:asc&size=50"   # 全域搜尋
curl -s -u "$AUTH" "$BASE/executions/search?size=10"           # 執行紀錄
```

> 搜尋介面在本 Kestra 版本僅支援 `page` / `size` / `sort`；`q`、`namespace`、`ids` 等過濾參數不生效，需要精確過濾時請改用 `/flows/{namespace}` 再於用戶端篩選。

### 4.2 flow id 命名要求

透過網關**讀 / 改 / 刪某個具體 flow**，或**建立 flow** 時，flow id 必須以 `<帳號>_` 開頭：

| 帳號 | 允許 | 拒絕（403） |
|---|---|---|
| `u199013` | `u199013_daily` | `u041007_daily`、`daily` |

命名空間層級的清單（`/flows/{namespace}`）與其它非 flow 介面不受此限制。

### 4.3 建立

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

> - 請求內容必須為 `application/x-yaml`。
> - 該 Kestra 版本的 flow 文件**沒有 `type` 欄位**（流程預設 DAG），任務**不支援 `dependsOn`**，帶上會回傳 422。

### 4.4 讀 / 改 / 刪

```bash
curl -s -u "$AUTH" "$BASE/flows/main/u199013_daily"                     # 讀
curl -s -u "$AUTH" -X PUT "$BASE/flows/main/u199013_daily" \
  -H 'Content-Type: application/x-yaml' --data-binary @/tmp/u199013_daily.yaml   # 改
curl -s -u "$AUTH" -X DELETE "$BASE/flows/main/u199013_daily"            # 刪
```

---

## 5. 健康檢查（含後端執行統計）

瀏覽器直接開啟 `https://kestra.feg.cn/api/v2/health` 會看到執行狀態儀表板（24 小時執行數、成功率、失敗/進行中/待處理、每小時趨勢、按命名空間與 Top Flows 表格，每 30 秒自動重新整理）；腳本 / curl 存取同一路徑則回傳 JSON。

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

- 後端無法連線時回傳 HTTP 503，`status` 變為 `degraded`，並帶有 `detail`（例外型別）
- 狀態口徑：`success` = SUCCESS，`failed` = FAILED，`running` = RUNNING（進行中），`pending` = CREATED（待處理），`paused` = PAUSED；`success_ratio` = success / (success + failed)
- 統計預設取過去 24 小時（`window.hours`），結果快取 30 秒

---

## 6. 錯誤碼

| 狀態碼 | 回應 | 原因 |
|---|---|---|
| 400 | `{"detail":"Tenant must be 'main'"}` | 請求帶了非 `main` 的租戶（`X-Kestra-Tenant` 標頭或 `?tenant=`） |
| 401 | `{"detail":"Unauthorized"}` | 缺少/錯誤的 Basic Auth，或帳號未配發 |
| 403 | `{"detail":"Forbidden"}` | 無權存取該資源 |
| 403 | `{"detail":"Flow id must be prefixed with '<帳號>_'"}` | flow id 不屬於目前帳號 |
| 404 | `{"detail":"Not Found"}` | 網關沒有該介面（例如 `/health`、`/api/v1/*`） |
| 其它 | Kestra 原始回應 | 上游回傳的狀態碼與內容原樣回傳 |
