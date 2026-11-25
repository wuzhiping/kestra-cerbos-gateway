#!/usr/bin/env python3
"""通过 Cerbos Admin API 部署策略。

Admin API：
    POST {CERBOS_URL}/admin/policy
    请求体：{"policies": [<策略文档>]}

用法：
    CERBOS_URL=http://10.17.1.201:3592 \
    CERBOS_ADMIN_USER=cerbos CERBOS_ADMIN_PASSWORD=cerbosAdmin \
    python3 cerbos/deploy_policy.py [策略文件...]
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request

import yaml

DEFAULT_POLICY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies")


def load_policies(paths):
    policies = []

    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        if not isinstance(doc, dict):
            raise ValueError(f"策略文件格式错误：{path}")

        policies.append(doc)

    return policies


def request(method: str, url: str, body=None):
    headers = {"Accept": "application/json"}

    if body is not None:
        headers["Content-Type"] = "application/json"

    user = os.getenv("CERBOS_ADMIN_USER", "cerbos")
    password = os.getenv("CERBOS_ADMIN_PASSWORD", "cerbosAdmin")
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("utf-8")
    headers["Authorization"] = f"Basic {token}"

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main() -> int:
    if len(sys.argv) > 1:
        paths = sys.argv[1:]
    else:
        paths = [
            os.path.join(DEFAULT_POLICY_DIR, name)
            for name in sorted(os.listdir(DEFAULT_POLICY_DIR))
            if name.endswith((".yaml", ".yml"))
        ]

    base = os.getenv("CERBOS_URL", "http://10.17.1.201:3592").rstrip("/")

    policies = load_policies(paths)

    status, text = request("POST", f"{base}/admin/policy", {"policies": policies})

    if status >= 400:
        print(f"部署失败（HTTP {status}）：{text}")
        return 1

    print(f"部署成功（HTTP {status}）：{text}")

    status, text = request("GET", f"{base}/admin/policies")

    if status < 400:
        print(f"当前策略列表：{text}")

    print("已部署策略文件：" + ", ".join(paths))

    return 0


if __name__ == "__main__":
    sys.exit(main())
