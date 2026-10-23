#!/usr/bin/env python3
"""Uni VPN: create a fresh account on every run and publish VLESS URIs to GitHub Gist."""

import json
import os
import ssl
import sys
import uuid
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode

BASE = "https://api.univconn.com"
GITHUB_API = "https://api.github.com"
PKG = "com.univconn.and"
CTX = ssl.create_default_context()


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
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
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


def build_vless_uri(node, ep, creds):
    if ep.get("protocol") != "vless":
        return None

    host = ep.get("server")
    port = ep.get("server_port")
    uid = creds.get("credential")

    if not host or not port or not uid:
        return None

    name = node.get("name") or "node"
    eid = ep.get("id", "")
    security = ep.get("security") or "tls"
    transport = ep.get("transport") or "tcp"
    sni = ep.get("server_name") or host

    params = {
        "encryption": "none",
        "security": "reality" if security == "reality" else "tls",
        "type": "ws" if transport in ("ws", "websocket") else transport,
        "sni": sni,
    }

    if security == "reality":
        if ep.get("reality_public_key"):
            params["pbk"] = ep["reality_public_key"]
        if ep.get("reality_short_id"):
            params["sid"] = ep["reality_short_id"]
        params["fp"] = ep.get("utls_fingerprint") or "chrome"

    if ep.get("flow"):
        params["flow"] = ep["flow"]

    if transport in ("ws", "websocket"):
        if ep.get("ws_path"):
            params["path"] = ep["ws_path"]
        if ep.get("ws_host"):
            params["host"] = ep["ws_host"]

    tag = f"{name}-vless-{security}-{transport}-{eid}"

    return (
        f"vless://{quote(str(uid), safe='')}@{host}:{port}"
        f"?{urlencode(params)}#{quote(tag, safe='')}"
    )


def main():
    gist_token = os.environ.get("GIST_TOKEN", "").strip()
    gist_id = os.environ.get("GIST_ID", "").strip()
    filename = os.environ.get(
        "GIST_FILENAME", "univpn_vless.txt"
    ).strip()

    if not gist_token or not gist_id:
        raise SystemExit("Missing GIST_TOKEN or GIST_ID secrets")

    # Create a fresh account and random HWID on every run.
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
        raise RuntimeError("Account response has no access_key")

    headers["X-Access-Key"] = access_key
    print("[+] Account created")

    # Fetch the complete node directory.
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

    # Request only VLESS credentials.
    print("[*] Requesting VLESS credentials")

    _, creds = http(
        BASE + "/v2/account/credentials",
        method="POST",
        headers=headers,
        body={"protocol": "vless"},
    )

    uris = []
    for node, ep in endpoints:
        uri = build_vless_uri(node, ep, creds)
        if uri:
            uris.append(uri)

    # Remove duplicates while preserving order.
    uris = list(dict.fromkeys(uris))

    if not uris:
        raise RuntimeError(
            "No valid VLESS URIs; existing Gist left unchanged"
        )

    content = "\n".join(uris) + "\n"

    # Update the existing Gist, preserving its URL.
    gist_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {gist_token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "UniVPN-VLESS-Updater",
    }

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
    print(f"[+] VLESS links: {len(uris)}")
    print(f"[+] File: {filename}")
    print(f"[+] URL: {result.get('html_url', '')}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
