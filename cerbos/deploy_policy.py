#!/usr/bin/env python3
"""通过 Cerbos Admin API 部署策略。

用法：
    CERBOS_URL=http://10.17.1.201:3592 \
    CERBOS_ADMIN_USER=cerbos CERBOS_ADMIN_PASSWORD=cerbosAdmin \
    python3 cerbos/deploy_policy.py cerbos/policies/mcp.yaml
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request

import yaml

DEFAULT_POLICY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "policies", "kestra-mcp.yaml"
)


def load_policy(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def request(method: str, url: str, body=None):
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    user = os.getenv("CERBOS_ADMIN_USER", "cerbos")
    password = os.getenv("CERBOS_ADMIN_PASSWORD", "cerbosAdmin")
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("utf-8")
    headers["Authorization"] = f"Basic {token}"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_POLICY
    base = os.getenv("CERBOS_URL", "http://10.17.1.201:3592").rstrip("/")

    policy = load_policy(path)

    status, text = request("POST", f"{base}/adminapi/policy", policy)
    if status >= 400:
        status, text = request("PUT", f"{base}/adminapi/policy", policy)

    if status >= 400:
        if "disabled" in text.lower():
            print("Cerbos Admin API 未启用。")
            print("请在 Cerbos 端开启 admin 服务（cerbos.yaml: admin.enabled: true），")
            print(f"或把 {path} 拷贝到 Cerbos 挂载的策略目录后重启 Cerbos。")
            print(text)
            return 2

        print(f"部署失败（HTTP {status}）：{text}")
        return 1

    print(f"部署成功（HTTP {status}）：{text}")
    print(f"策略文件：{path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
