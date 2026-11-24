
#!/usr/bin/env python3
"""Uni VPN: create a fresh account and publish VLESS URIs to GitHub Gist."""

import json
import os
import ssl
import sys
import uuid
import copy
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode

BASE = "https://api.univconn.com"
GITHUB_API = "https://api.github.com"
PKG = "com.univconn.and"
CTX = ssl.create_default_context()

IP_LAST_OCTETS = (4, 9, 7, 11)


def http(url, method="GET", headers=None, body=None, timeout=25):
    h = dict(headers or {})
    data = None

    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        h["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url, data=data, headers=h, method=method
    )

    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=CTX
        ) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}

    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")

        try:
            detail = json.loads(raw)
        except Exception:
            detail = raw[:500]

        raise RuntimeError(
            f"HTTP {e.code} {url}: {detail}"
        ) from e


def build_vless_uris(node, ep, creds):
    if ep.get("protocol") != "vless":
        return []

    host = ep.get("server")
    port = ep.get("server_port")
    uid = creds.get("credential")

    if not host or not port or not uid:
        return []

    # Проверяем IPv4.
    parts = str(host).split(".")

    if len(parts) != 4:
        return []

    try:
        if not all(
            p.isdigit() and 0 <= int(p) <= 255
            for p in parts
        ):
            return []
    except (ValueError, TypeError):
        return []

    name = node.get("name") or "node"
    eid = ep.get("id", "")

    security = ep.get("security") or "tls"
    transport = ep.get("transport") or "tcp"
    sni = ep.get("server_name") or host

    # Создаём параметры один раз для данного endpoint.
    base_params = {
        "encryption": "none",
        "security": (
            "reality" if security == "reality" else "tls"
        ),
        "type": (
            "ws" if transport in ("ws", "websocket")
            else transport
        ),
        "sni": sni,
    }

    # REALITY
    if security == "reality":
        if ep.get("reality_public_key"):
            base_params["pbk"] = ep["reality_public_key"]

        if ep.get("reality_short_id"):
            base_params["sid"] = ep["reality_short_id"]

        fingerprint = ep.get("utls_fingerprint")

        if fingerprint:
            base_params["fp"] = fingerprint

    # FLOW
    if ep.get("flow"):
        base_params["flow"] = ep["flow"]

    # WEBSOCKET
    if transport in ("ws", "websocket"):
        if ep.get("ws_path"):
            base_params["path"] = ep["ws_path"]

        if ep.get("ws_host"):
            base_params["host"] = ep["ws_host"]

    # Фиксируем параметры, чтобы все IP имели одинаковые значения.
    fixed_params = copy.deepcopy(base_params)

    uris = []

    for last_octet in IP_LAST_OCTETS:
        new_host = ".".join(
            parts[:3] + [str(last_octet)]
        )

        tag = (
            f"{name}-vless-{security}-"
            f"{transport}-{eid}-{last_octet}"
        )

        uri = (
            f"vless://{quote(str(uid), safe='')}@"
            f"{new_host}:{port}"
            f"?{urlencode(copy.deepcopy(fixed_params))}"
            f"#{quote(tag, safe='')}"
        )

        uris.append(uri)

    return uris


def main():
    gist_token = os.environ.get(
        "GIST_TOKEN", ""
    ).strip()

    gist_id = os.environ.get(
        "GIST_ID", ""
    ).strip()

    filename = os.environ.get(
        "GIST_FILENAME", "univpn_vless.txt"
    ).strip()

    if not gist_token or not gist_id:
        raise SystemExit(
            "Missing GIST_TOKEN or GIST_ID secrets"
        )

    # Новый HWID при каждом запуске.
    hwid = uuid.uuid4().hex

    headers = {
        "Accept": "application/json",
        "User-Agent": "Dart/3.5 (dart:io)",
        "X-Package-Name": PKG,
        "X-HwID": hwid,
        "X-App-Version": "1.0.16",
        "X-Client-Platform": "android",
        "X-Distribution": "google",
    }

    print("[*] Creating a new Uni VPN account")

    _, account = http(
        BASE + "/public/account/create",
        method="POST",
        headers=headers,
        body={
            "hwid": hwid,
            "platform": "android",
            "package": PKG,
        },
    )

    access_key = account.get("access_key")

    if not access_key:
        raise RuntimeError(
            "Account response has no access_key"
        )

    headers["X-Access-Key"] = access_key

    print("[+] Account created")

    # Получаем полный каталог серверов.
    print("[*] Fetching node directory")

    _, directory = http(
        BASE + "/v2/account/directory",
        headers=headers,
    )

    nodes = directory.get("nodes") or []

    endpoints = [
        (node, ep)
        for node in nodes
        for ep in (node.get("endpoints") or [])
        if ep.get("protocol") == "vless"
    ]

    print(f"[+] Nodes: {len(nodes)}")
    print(f"[+] VLESS endpoints: {len(endpoints)}")

    if not endpoints:
        raise RuntimeError(
            "No VLESS endpoints; existing Gist left unchanged"
        )

    # Запрашиваем credentials только для VLESS.
    print("[*] Requesting VLESS credentials")

    _, creds = http(
        BASE + "/v2/account/credentials",
        method="POST",
        headers=headers,
        body={"protocol": "vless"},
    )

    # Генерируем три ссылки на каждый endpoint.
    uris = []

    for node, ep in endpoints:
        generated = build_vless_uris(
            node, ep, creds
        )

        uris.extend(generated)

    # Удаляем дубликаты, сохраняя порядок.
    uris = list(dict.fromkeys(uris))

    if not uris:
        raise RuntimeError(
            "No valid VLESS URIs; existing Gist left unchanged"
        )

    content = "\n".join(uris) + "\n"

    # Обновляем существующий Gist.
    gist_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {gist_token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "UniVPN-VLESS-Updater",
    }

    print("[*] Updating GitHub Gist")

    _, result = http(
        f"{GITHUB_API}/gists/{gist_id}",
        method="PATCH",
        headers=gist_headers,
        body={
            "files": {
                filename: {
                    "content": content
                }
            }
        },
    )

    print("[+] Gist updated")
    print(f"[+] Original VLESS endpoints: {len(endpoints)}")
    print(f"[+] IP variants per endpoint: {len(IP_LAST_OCTETS)}")
    print(f"[+] Total VLESS links: {len(uris)}")
    print(f"[+] File: {filename}")
    print(f"[+] URL: {result.get('html_url', '')}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
