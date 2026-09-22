#!/usr/bin/env python3

import base64
import json
import os
import random
import re
import socket
import string
import uuid

from urllib.parse import quote, urlencode

import requests


# ============================================================
# CONFIG
# ============================================================

BASE_URL = "https://bos.tg"

MY_TOKEN = os.getenv("MY_TOKEN")
GIST_ID = os.getenv("GIST_ID")

GIST_FILENAME = "bosvpn.txt"
GIST_DESCRIPTION = "Auto-updated BoSVPN configs"

OUTPUT_FILE = "configs.txt"

NEW_SNI = "rbc.ru"

HAPP_USER_AGENT = "Happ/4.1.0/Android/17860741775021899610"


# ============================================================
# DNS CACHE
# ============================================================

DNS_CACHE = {}


def resolve_host(host):

    if not host:
        return host

    host = str(host).strip()

    # Уже IPv4
    if re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        host
    ):
        return host

    if host in DNS_CACHE:
        return DNS_CACHE[host]

    try:

        infos = socket.getaddrinfo(
            host,
            None,
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        for info in infos:

            ip = info[4][0]

            if ip:

                DNS_CACHE[host] = ip

                print(
                    f"[DNS] {host} -> {ip}"
                )

                return ip

    except Exception as e:

        print(
            f"[DNS] {host}: {e}"
        )

    DNS_CACHE[host] = host

    return host


# ============================================================
# ENCODE
# ============================================================

def enc(value):

    return quote(
        str(value),
        safe=""
    )


# ============================================================
# VLESS
# ============================================================

def make_vless(outbound, remark):

    settings = outbound.get(
        "settings",
        {}
    )

    stream = outbound.get(
        "streamSettings",
        {}
    )

    if not isinstance(settings, dict):
        settings = {}

    if not isinstance(stream, dict):
        stream = {}

    vnext = settings.get(
        "vnext",
        []
    )

    if not isinstance(vnext, list) or not vnext:
        return None

    server = vnext[0]

    if not isinstance(server, dict):
        return None

    original_address = server.get(
        "address",
        ""
    )

    port = server.get(
        "port",
        443
    )

    users = server.get(
        "users",
        []
    )

    if not users:
        return None

    user = users[0]

    if not isinstance(user, dict):
        return None

    user_uuid = (
        user.get("id")
        or user.get("uuid")
        or ""
    )

    if not original_address or not user_uuid:
        return None

    address = resolve_host(
        original_address
    )

    params = {}

    # --------------------------------------------------------
    # NETWORK
    # --------------------------------------------------------

    network = str(
        stream.get(
            "network",
            ""
        )
    ).lower()

    if network:
        params["type"] = network

    # --------------------------------------------------------
    # SECURITY
    # --------------------------------------------------------

    security = str(
        stream.get(
            "security",
            ""
        )
    ).lower()

    if security:
        params["security"] = security

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    tls = stream.get(
        "tlsSettings",
        {}
    )

    if not isinstance(tls, dict):
        tls = {}

    if security == "tls":

        params["sni"] = NEW_SNI

        fingerprint = tls.get(
            "fingerprint"
        )

        if fingerprint:
            params["fp"] = str(
                fingerprint
            )

    # --------------------------------------------------------
    # WS
    # --------------------------------------------------------

    if network == "ws":

        ws = stream.get(
            "wsSettings",
            {}
        )

        if isinstance(ws, dict):

            path = ws.get(
                "path"
            )

            if path:
                params["path"] = path

            headers = ws.get(
                "headers",
                {}
            )

            if isinstance(headers, dict):

                host = headers.get(
                    "Host"
                )

                if host:
                    params["host"] = host

    # --------------------------------------------------------
    # GRPC
    # --------------------------------------------------------

    elif network == "grpc":

        grpc = stream.get(
            "grpcSettings",
            {}
        )

        if isinstance(grpc, dict):

            service_name = (
                grpc.get("serviceName")
                or grpc.get("service_name")
                or ""
            )

            if service_name:

                params["serviceName"] = (
                    service_name
                )

            mode = grpc.get(
                "mode"
            )

            if mode:

                params["mode"] = mode

            authority = grpc.get(
                "authority"
            )

            if authority:

                params["authority"] = (
                    authority
                )

    # --------------------------------------------------------
    # XHTTP
    # --------------------------------------------------------

    elif network == "xhttp":

        xhttp = stream.get(
            "xhttpSettings",
            {}
        )

        if isinstance(xhttp, dict):

            path = xhttp.get(
                "path"
            )

            if path:
                params["path"] = path

            mode = xhttp.get(
                "mode"
            )

            if mode:
                params["mode"] = mode

            host = xhttp.get(
                "host"
            )

            if host:
                params["host"] = host

            extra = xhttp.get(
                "extra"
            )

            if extra is not None:

                if isinstance(extra, str):

                    params["extra"] = extra

                else:

                    params["extra"] = json.dumps(
                        extra,
                        ensure_ascii=False,
                        separators=(",", ":")
                    )

    # --------------------------------------------------------
    # REALITY
    # --------------------------------------------------------

    reality = stream.get(
        "realitySettings",
        {}
    )

    if isinstance(reality, dict) and reality:

        params["sni"] = NEW_SNI

        public_key = (
            reality.get("publicKey")
            or reality.get("pbk")
        )

        if public_key:
            params["pbk"] = public_key

        short_id = (
            reality.get("shortId")
            or reality.get("sid")
        )

        if short_id:
            params["sid"] = short_id

        spider_x = (
            reality.get("spiderX")
            or reality.get("spx")
        )

        if spider_x:
            params["spx"] = spider_x

        fingerprint = reality.get(
            "fingerprint"
        )

        if fingerprint:
            params["fp"] = fingerprint

    # --------------------------------------------------------
    # FLOW
    # --------------------------------------------------------

    flow = user.get(
        "flow"
    )

    if flow:
        params["flow"] = flow

    # --------------------------------------------------------
    # BUILD
    # --------------------------------------------------------

    query = urlencode(
        params,
        doseq=True
    )

    return (
        "vless://"
        + enc(user_uuid)
        + "@"
        + address
        + ":"
        + str(port)
        + "/?"
        + query
        + "#"
        + enc(
            remark or "VLESS"
        )
    )


# ============================================================
# HYSTERIA / HYSTERIA2
# ============================================================

def make_hysteria(outbound, remark):

    settings = outbound.get(
        "settings",
        {}
    )

    stream = outbound.get(
        "streamSettings",
        {}
    )

    if not isinstance(settings, dict):
        settings = {}

    if not isinstance(stream, dict):
        stream = {}

    hysteria = stream.get(
        "hysteriaSettings",
        {}
    )

    if not isinstance(hysteria, dict):
        hysteria = {}

    # --------------------------------------------------------
    # ADDRESS
    # --------------------------------------------------------

    address = (
        settings.get("address")
        or outbound.get("address")
        or hysteria.get("address")
        or ""
    )

    port = (
        settings.get("port")
        or outbound.get("port")
        or hysteria.get("port")
        or ""
    )

    # --------------------------------------------------------
    # AUTH
    # --------------------------------------------------------

    auth = (
        hysteria.get("auth")
        or settings.get("auth")
        or outbound.get("auth")
        or ""
    )

    if not address or not port or not auth:

        print(
            "[-] Hysteria: missing "
            "address/port/auth"
        )

        return None

    original_address = str(
        address
    )

    address = resolve_host(
        original_address
    )

    # --------------------------------------------------------
    # QUERY
    # --------------------------------------------------------

    params = {
        "sni": NEW_SNI,
        "insecure": "0"
    }

    # ALPN intentionally not added

    # --------------------------------------------------------
    # OBFUSCATION
    # --------------------------------------------------------

    obfs = (
        hysteria.get("obfs")
        or settings.get("obfs")
    )

    if obfs:

        params["obfs"] = str(
            obfs
        )

    obfs_password = (
        hysteria.get("obfs-password")
        or hysteria.get("obfsPassword")
        or settings.get("obfs-password")
        or settings.get("obfsPassword")
    )

    if obfs_password:

        params["obfs-password"] = str(
            obfs_password
        )

    query = urlencode(
        params,
        doseq=True
    )

    return (
        "hysteria2://"
        + enc(auth)
        + "@"
        + address
        + ":"
        + str(port)
        + "/?"
        + query
        + "#"
        + enc(
            remark or "Hysteria"
        )
    )


# ============================================================
# TROJAN
# ============================================================

def make_trojan(outbound, remark):

    settings = outbound.get(
        "settings",
        {}
    )

    stream = outbound.get(
        "streamSettings",
        {}
    )

    if not isinstance(settings, dict):
        settings = {}

    if not isinstance(stream, dict):
        stream = {}

    servers = settings.get(
        "servers",
        []
    )

    if not servers:
        return None

    server = servers[0]

    if not isinstance(server, dict):
        return None

    original_address = server.get(
        "address",
        ""
    )

    port = server.get(
        "port",
        443
    )

    password = server.get(
        "password",
        ""
    )

    if not original_address or not password:
        return None

    address = resolve_host(
        original_address
    )

    params = {}

    network = str(
        stream.get(
            "network",
            ""
        )
    ).lower()

    security = str(
        stream.get(
            "security",
            ""
        )
    ).lower()

    if network:
        params["type"] = network

    if security:
        params["security"] = security

    if security == "tls":
        params["sni"] = NEW_SNI

    # --------------------------------------------------------
    # WS
    # --------------------------------------------------------

    ws = stream.get(
        "wsSettings",
        {}
    )

    if isinstance(ws, dict):

        if ws.get("path"):
            params["path"] = ws["path"]

        headers = ws.get(
            "headers",
            {}
        )

        if isinstance(headers, dict):

            if headers.get("Host"):
                params["host"] = (
                    headers["Host"]
                )

    # --------------------------------------------------------
    # GRPC
    # --------------------------------------------------------

    grpc = stream.get(
        "grpcSettings",
        {}
    )

    if isinstance(grpc, dict):

        if grpc.get("serviceName"):
            params["serviceName"] = (
                grpc["serviceName"]
            )

        if grpc.get("mode"):
            params["mode"] = (
                grpc["mode"]
            )

        if grpc.get("authority"):
            params["authority"] = (
                grpc["authority"]
            )

    query = urlencode(
        params,
        doseq=True
    )

    return (
        "trojan://"
        + enc(password)
        + "@"
        + address
        + ":"
        + str(port)
        + "/?"
        + query
        + "#"
        + enc(
            remark or "Trojan"
        )
    )


# ============================================================
# SHADOWSOCKS
# ============================================================

def make_ss(outbound, remark):

    settings = outbound.get(
        "settings",
        {}
    )

    if not isinstance(settings, dict):
        return None

    servers = settings.get(
        "servers",
        []
    )

    if not servers:
        return None

    server = servers[0]

    if not isinstance(server, dict):
        return None

    original_address = server.get(
        "address",
        ""
    )

    port = server.get(
        "port",
        443
    )

    method = server.get(
        "method",
        ""
    )

    password = server.get(
        "password",
        ""
    )

    if (
        not original_address
        or not method
        or not password
    ):
        return None

    address = resolve_host(
        original_address
    )

    userinfo = (
        method
        + ":"
        + password
    )

    encoded = (
        base64.urlsafe_b64encode(
            userinfo.encode()
        )
        .decode()
        .rstrip("=")
    )

    return (
        "ss://"
        + encoded
        + "@"
        + address
        + ":"
        + str(port)
        + "#"
        + enc(
            remark or "Shadowsocks"
        )
    )


# ============================================================
# RECURSIVE SCANNER
# ============================================================

def scan(obj, results):

    if isinstance(obj, dict):

        outbounds = obj.get(
            "outbounds"
        )

        if isinstance(
            outbounds,
            list
        ):

            remark = (
                obj.get("remarks")
                or obj.get("remark")
                or ""
            )

            for outbound in outbounds:

                if not isinstance(
                    outbound,
                    dict
                ):
                    continue

                protocol = str(
                    outbound.get(
                        "protocol",
                        ""
                    )
                ).lower()

                link = None

                # ------------------------------------------------
                # VLESS
                # ------------------------------------------------

                if protocol == "vless":

                    link = make_vless(
                        outbound,
                        remark
                    )

                # ------------------------------------------------
                # HYSTERIA
                # ------------------------------------------------

                elif protocol in {
                    "hysteria",
                    "hysteria2"
                }:

                    link = make_hysteria(
                        outbound,
                        remark
                    )

                # ------------------------------------------------
                # TROJAN
                # ------------------------------------------------

                elif protocol == "trojan":

                    link = make_trojan(
                        outbound,
                        remark
                    )

                # ------------------------------------------------
                # SS
                # ------------------------------------------------

                elif protocol in {
                    "shadowsocks",
                    "ss"
                }:

                    link = make_ss(
                        outbound,
                        remark
                    )

                if link:

                    results.append({
                        "protocol": protocol,
                        "remark": remark,
                        "link": link
                    })

        # Ищем вложенные JSON-структуры
        for value in obj.values():

            scan(
                value,
                results
            )

    elif isinstance(obj, list):

        for value in obj:

            scan(
                value,
                results
            )


# ============================================================
# GITHUB GIST
# ============================================================

def save_to_gist(content):

    if not MY_TOKEN:

        print(
            "\n[!] MY_TOKEN не задан."
        )

        return False

    headers = {
        "Authorization":
            f"token {MY_TOKEN}",

        "Accept":
            "application/vnd.github.v3+json",

        "Content-Type":
            "application/json"
    }

    payload = {
        "description":
            GIST_DESCRIPTION,

        "public":
            False,

        "files": {
            GIST_FILENAME: {
                "content":
                    content
            }
        }
    }

    try:

        if GIST_ID:

            url = (
                "https://api.github.com/gists/"
                + GIST_ID
            )

            print(
                "\n[*] Обновляем Gist..."
            )

            response = requests.patch(
                url,
                json=payload,
                headers=headers,
                timeout=30
            )

        else:

            url = (
                "https://api.github.com/gists"
            )

            print(
                "\n[*] Создаём Gist..."
            )

            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30
            )

    except Exception as e:

        print(
            "[-] Gist error:",
            e
        )

        return False

    if response.status_code in {
        200,
        201
    }:

        try:
            data = response.json()
        except Exception:
            data = {}

        print(
            "[+] Gist успешно сохранён"
        )

        print(
            "[+] Gist:",
            data.get("html_url")
        )

        return True

    print(
        "[-] GitHub Gist error:",
        response.status_code
    )

    print(
        response.text[:3000]
    )

    return False


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=================================================="
    )

    print(
        "       BoSVPN CONFIG EXTRACTOR"
    )

    print(
        "=================================================="
    )

    session = requests.Session()

    session.headers.update({
        "User-Agent":
            HAPP_USER_AGENT,

        "Accept":
            "*/*"
    })

    # ========================================================
    # RANDOM ACCOUNT
    # ========================================================

    email = (
        "".join(
            random.choices(
                string.ascii_lowercase
                + string.digits,
                k=10
            )
        )
        + "@gmail.com"
    )

    client_id = str(
        uuid.uuid4()
    )

    hwid = str(
        uuid.uuid4()
    )

    print(
        "[*] Email:",
        email
    )

    print(
        "[*] Client-ID:",
        client_id
    )

    print(
        "[*] HWID:",
        hwid
    )

    print(
        "[*] User-Agent:",
        HAPP_USER_AGENT
    )

    # ========================================================
    # LOGIN
    # ========================================================

    print(
        "\n[*] LOGIN..."
    )

    try:

        response = session.post(

            f"{BASE_URL}/api/auth/login",

            json={

                "email":
                    email,

                "clientId":
                    client_id,

                "hwid":
                    hwid,

                "platform":
                    "android",

                "osVersion":
                    "14",

                "appVersion":
                    "4.1.0",

                "deviceModel":
                    "Pixel 7",

                "manufacturer":
                    "Google"
            },

            timeout=30
        )

    except Exception as e:

        print(
            "[-] LOGIN error:",
            e
        )

        return

    print(
        "[+] Login HTTP:",
        response.status_code
    )

    if response.status_code != 200:

        print(
            response.text[:3000]
        )

        return

    try:

        login_data = response.json()

    except Exception as e:

        print(
            "[-] Login JSON error:",
            e
        )

        print(
            response.text[:3000]
        )

        return

    if "accessToken" not in login_data:

        print(
            "[-] accessToken отсутствует"
        )

        print(
            json.dumps(
                login_data,
                ensure_ascii=False,
                indent=2
            )[:5000]
        )

        return

    print(
        "[+] Авторизация успешна"
    )

    # ========================================================
    # SUBSCRIPTION URL
    # ========================================================

    try:

        sub_url = (
            login_data
            ["user"]
            ["access"]
            ["premium"]
            ["subscriptionUrl"]
        )

    except Exception as e:

        print(
            "[-] subscriptionUrl не найден:",
            e
        )

        return

    print(
        "\n[+] Subscription URL:"
    )

    print(
        sub_url
    )

    # ========================================================
    # SUBSCRIPTION ENDPOINT
    # ========================================================

    real_sub_url = sub_url.strip()

    print(
        "\n[+] Subscription endpoint:"
    )

    print(
        real_sub_url
    )

    # ========================================================
    # HAPP SUBSCRIPTION
    # ========================================================

    print(
        "\n[*] Получаем подписку через Happ..."
    )

    headers = {

        "User-Agent":
            HAPP_USER_AGENT,

        "X-HWID":
            hwid,

        "Accept":
            "application/json",

        "Accept-Encoding":
            "gzip, deflate, br"
    }

    try:

        sub_response = requests.get(

            real_sub_url,

            headers=headers,

            timeout=30
        )

    except Exception as e:

        print(
            "[-] Subscription error:",
            e
        )

        return

    print(
        "[+] Subscription HTTP:",
        sub_response.status_code
    )

    print(
        "[+] Content-Type:",
        sub_response.headers.get(
            "Content-Type"
        )
    )

    print(
        "[+] Content-Encoding:",
        sub_response.headers.get(
            "Content-Encoding"
        )
    )

    print(
        "[+] Size:",
        len(sub_response.content)
    )

    if sub_response.status_code != 200:

        print(
            sub_response.text[:3000]
        )

        return

    if sub_response.headers.get(
        "X-Hwid-Not-Supported"
    ):

        print(
            "[-] Сервер отклонил HWID"
        )

        return

    # ========================================================
    # JSON
    # ========================================================

    body = sub_response.content

    print(
        "\n[*] Разбираем JSON..."
    )

    try:

        data = json.loads(
            body.decode(
                "utf-8",
                errors="replace"
            )
        )

    except Exception as e:

        print(
            "[-] JSON error:",
            e
        )

        print(
            "\n----- RESPONSE -----"
        )

        print(
            body[:5000].decode(
                "utf-8",
                errors="replace"
            )
        )

        print(
            "--------------------"
        )

        return

    print(
        "[+] JSON успешно разобран"
    )

    # ========================================================
    # SAVE JSON
    # ========================================================

    try:

        with open(
            "subscription.json",
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                ensure_ascii=False,
                indent=2
            )

        print(
            "[+] subscription.json сохранён"
        )

    except Exception as e:

        print(
            "[!] Не удалось сохранить JSON:",
            e
        )

    # ========================================================
    # EXTRACT
    # ========================================================

    print(
        "\n=================================================="
    )

    print(
        "             ИЩЕМ КОНФИГУРАЦИИ"
    )

    print(
        "=================================================="
    )

    results = []

    scan(
        data,
        results
    )

    print(
        "\n[+] Найдено:",
        len(results)
    )

    # ========================================================
    # DEDUPLICATE
    # ========================================================

    unique = []

    seen = set()

    for item in results:

        link = item["link"]

        if link in seen:
            continue

        seen.add(link)

        unique.append(
            item
        )

    results = unique

    # ========================================================
    # COUNTS
    # ========================================================

    counts = {}

    for item in results:

        protocol = item["protocol"]

        counts[protocol] = (
            counts.get(
                protocol,
                0
            )
            + 1
        )

    # ========================================================
    # FINAL CONTENT
    # ========================================================

    final_content = "\n".join(
        item["link"]
        for item in results
    )

    if final_content:

        final_content += "\n"

    # ========================================================
    # SAVE LOCAL FILE
    # ========================================================

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:

        f.write(
            final_content
        )

    print(
        "\n[+] configs.txt создан"
    )

    print(
        "[+] Размер:",
        os.path.getsize(
            OUTPUT_FILE
        ),
        "bytes"
    )

    # ========================================================
    # RESULT
    # ========================================================

    print(
        "\n=================================================="
    )

    print(
        "                  РЕЗУЛЬТАТ"
    )

    print(
        "=================================================="
    )

    for protocol in sorted(counts):

        print(
            f"[+] {protocol}: "
            f"{counts[protocol]}"
        )

    print(
        "[+] TOTAL:",
        len(results)
    )

    # ========================================================
    # LINKS
    # ========================================================

    print(
        "\n=================================================="
    )

    print(
        "                 CONFIG LINKS"
    )

    print(
        "=================================================="
    )

    for i, item in enumerate(
        results,
        1
    ):

        print(
            f"\n[{i}] "
            f"{item['protocol']} "
            f"{item['remark']}"
        )

        print(
            item["link"]
        )

    # ========================================================
    # GITHUB GIST
    # ========================================================

    save_to_gist(
        final_content
    )

    # ========================================================
    # DONE
    # ========================================================

    print(
        "\n=================================================="
    )

    print(
        "                     DONE"
    )

    print(
        "=================================================="
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
