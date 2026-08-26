#!/usr/bin/env python3

import base64
import json
import os
import random
import re
import socket
import string
import uuid

from urllib.parse import urlencode, quote

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

# SNI для VLESS и Hysteria2
SNI = "rbc.ru"

# ============================================================
# DNS
# ============================================================

DNS_CACHE = {}


def is_ipv4(value):
    return bool(
        re.fullmatch(
            r"\d{1,3}(?:\.\d{1,3}){3}",
            str(value or "")
        )
    )


def resolve_host(host):
    """
    Hostname -> IPv4.
    Если уже IPv4 — оставляем без изменений.
    """

    host = str(host or "").strip()

    if not host:
        return host

    if is_ipv4(host):
        return host

    if host in DNS_CACHE:
        return DNS_CACHE[host]

    try:
        ip = socket.gethostbyname(host)
        DNS_CACHE[host] = ip

        print(f"[DNS] {host} -> {ip}")

        return ip

    except Exception as e:
        print(f"[DNS] Не удалось разрешить {host}: {e}")

        DNS_CACHE[host] = host

        return host


# ============================================================
# ALPN
# ============================================================

REMOVE_ALPN = {
    "h2",
    "http/1.1",
}


def clean_alpn(value):
    """
    Удаляет h2 и http/1.1 из ALPN.

    Например:

        h2
        http/1.1
        h2,http/1.1

    -> None

    Если есть другие значения, они сохраняются.
    """

    if value is None:
        return None

    if isinstance(value, list):

        result = []

        for item in value:

            item = str(item).strip()

            if not item:
                continue

            if item.lower() in REMOVE_ALPN:
                continue

            result.append(item)

        return result if result else None

    value = str(value).strip()

    if not value:
        return None

    parts = []

    for item in value.split(","):

        item = item.strip()

        if not item:
            continue

        if item.lower() in REMOVE_ALPN:
            continue

        parts.append(item)

    if not parts:
        return None

    return ",".join(parts)


# ============================================================
# QUERY
# ============================================================

def build_query(params):
    return urlencode(
        params,
        doseq=True
    )


# ============================================================
# VLESS
# ============================================================

def build_vless(outbound, remark=""):

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

    # --------------------------------------------------------
    # SERVER
    # --------------------------------------------------------

    address = ""
    port = ""
    users = []

    vnext = settings.get(
        "vnext",
        []
    )

    if isinstance(vnext, list) and vnext:

        server = vnext[0]

        if isinstance(server, dict):

            address = server.get(
                "address",
                ""
            )

            port = server.get(
                "port",
                ""
            )

            users = server.get(
                "users",
                []
            )

    else:

        address = (
            settings.get("address")
            or outbound.get("address")
            or ""
        )

        port = (
            settings.get("port")
            or outbound.get("port")
            or ""
        )

        users = settings.get(
            "users",
            []
        )

    if not users:
        print("[-] VLESS: users не найден")
        return None

    user = users[0]

    if not isinstance(user, dict):
        return None

    uuid_value = (
        user.get("id")
        or user.get("uuid")
        or ""
    )

    if not uuid_value:
        print("[-] VLESS: UUID не найден")
        return None

    if not address or not port:
        print("[-] VLESS: address/port отсутствует")
        return None

    # --------------------------------------------------------
    # DNS HOST -> IP
    # --------------------------------------------------------

    ip = resolve_host(address)

    # --------------------------------------------------------
    # STREAM
    # --------------------------------------------------------

    network = str(
        stream.get(
            "network",
            "tcp"
        )
    ).lower()

    security = str(
        stream.get(
            "security",
            ""
        )
    ).lower()

    params = []

    # type
    if network:
        params.append(
            ("type", network)
        )

    # security
    if security:
        params.append(
            ("security", security)
        )

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

        # ВСЕГДА rbc.ru
        params.append(
            ("sni", SNI)
        )

        # fingerprint
        fingerprint = tls.get(
            "fingerprint"
        )

        if fingerprint:
            params.append(
                ("fp", str(fingerprint))
            )

        # ALPN
        alpn = clean_alpn(
            tls.get("alpn")
        )

        if alpn:

            if isinstance(alpn, list):
                alpn_value = ",".join(alpn)
            else:
                alpn_value = str(alpn)

            if alpn_value:
                params.append(
                    ("alpn", alpn_value)
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
                params.append(
                    ("path", path)
                )

            headers = ws.get(
                "headers",
                {}
            )

            if isinstance(headers, dict):

                host = (
                    headers.get("Host")
                    or headers.get("host")
                )

                if host:
                    params.append(
                        ("host", host)
                    )

    # --------------------------------------------------------
    # gRPC
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
                params.append(
                    (
                        "serviceName",
                        service_name
                    )
                )

            mode = grpc.get(
                "mode"
            )

            if mode:
                params.append(
                    ("mode", mode)
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
                params.append(
                    ("path", path)
                )

            host = xhttp.get(
                "host"
            )

            if host:
                params.append(
                    ("host", host)
                )

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    elif network == "tcp":

        tcp = stream.get(
            "tcpSettings",
            {}
        )

        if isinstance(tcp, dict):

            header = tcp.get(
                "header",
                {}
            )

            if isinstance(header, dict):

                header_type = header.get(
                    "type"
                )

                if header_type and header_type != "none":
                    params.append(
                        ("headerType", header_type)
                    )

    # --------------------------------------------------------
    # REALITY
    # --------------------------------------------------------

    reality = stream.get(
        "realitySettings"
    )

    if isinstance(reality, dict):

        # Reality тоже получает rbc.ru
        params.append(
            ("sni", SNI)
        )

        public_key = (
            reality.get("publicKey")
            or reality.get("pbk")
        )

        if public_key:
            params.append(
                ("pbk", public_key)
            )

        short_id = (
            reality.get("shortId")
            or reality.get("sid")
        )

        if short_id:
            params.append(
                ("sid", short_id)
            )

        spider_x = (
            reality.get("spiderX")
            or reality.get("spx")
        )

        if spider_x:
            params.append(
                ("spx", spider_x)
            )

        reality_fp = reality.get(
            "fingerprint"
        )

        if reality_fp:
            params.append(
                ("fp", reality_fp)
            )

    # --------------------------------------------------------
    # FLOW
    # --------------------------------------------------------

    flow = user.get(
        "flow"
    )

    if flow:
        params.append(
            ("flow", flow)
        )

    # --------------------------------------------------------
    # URI
    # --------------------------------------------------------

    query = build_query(
        params
    )

    fragment = quote(
        str(remark),
        safe=""
    )

    return (
        f"vless://"
        f"{uuid_value}@"
        f"{ip}:{port}"
        f"/?"
        f"{query}"
        f"#{fragment}"
    )


# ============================================================
# HYSTERIA2
# ============================================================

def build_hysteria(outbound, remark=""):

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

    hysteria_settings = stream.get(
        "hysteriaSettings",
        {}
    )

    if not isinstance(hysteria_settings, dict):
        hysteria_settings = {}

    # --------------------------------------------------------
    # ADDRESS
    # --------------------------------------------------------

    address = (
        settings.get("address")
        or outbound.get("address")
        or hysteria_settings.get("address")
        or ""
    )

    port = (
        settings.get("port")
        or outbound.get("port")
        or hysteria_settings.get("port")
        or ""
    )

    if not address or not port:
        print(
            "[-] Hysteria: address/port отсутствует"
        )
        return None

    # --------------------------------------------------------
    # AUTH
    # --------------------------------------------------------

    auth = (
        hysteria_settings.get("auth")
        or settings.get("auth")
        or outbound.get("auth")
        or ""
    )

    if not auth:
        print(
            "[-] Hysteria: auth отсутствует"
        )
        return None

    # --------------------------------------------------------
    # DNS HOST -> IP
    # --------------------------------------------------------

    ip = resolve_host(
        address
    )

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    tls = stream.get(
        "tlsSettings",
        {}
    )

    if not isinstance(tls, dict):
        tls = {}

    params = [
        ("sni", SNI),
        ("insecure", "0"),
    ]

    # --------------------------------------------------------
    # ALPN
    # --------------------------------------------------------

    alpn = clean_alpn(
        tls.get("alpn")
    )

    if alpn:

        if isinstance(alpn, list):
            alpn_value = ",".join(alpn)
        else:
            alpn_value = str(alpn)

        if alpn_value:
            params.append(
                ("alpn", alpn_value)
            )

    # --------------------------------------------------------
    # OBFUSCATION
    # --------------------------------------------------------

    obfs = (
        hysteria_settings.get("obfs")
        or settings.get("obfs")
        or outbound.get("obfs")
    )

    if obfs:
        params.append(
            ("obfs", str(obfs))
        )

    # --------------------------------------------------------
    # BUILD
    # --------------------------------------------------------

    query = build_query(
        params
    )

    fragment = quote(
        str(remark),
        safe=""
    )

    return (
        f"hysteria2://"
        f"{quote(str(auth), safe='')}@"
        f"{ip}:{port}"
        f"/?"
        f"{query}"
        f"#{fragment}"
    )


# ============================================================
# RECURSIVE EXTRACTOR
# ============================================================

def extract_configs(obj, result):

    if isinstance(obj, dict):

        outbounds = obj.get(
            "outbounds"
        )

        if isinstance(outbounds, list):

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

                # ------------------------------------------------
                # VLESS
                # ------------------------------------------------

                if protocol == "vless":

                    uri = build_vless(
                        outbound,
                        remark
                    )

                    if uri:

                        result.append(uri)

                        print(
                            "[+] VLESS:",
                            remark
                        )

                # ------------------------------------------------
                # HYSTERIA
                # ------------------------------------------------

                elif protocol in {
                    "hysteria",
                    "hysteria2"
                }:

                    uri = build_hysteria(
                        outbound,
                        remark
                    )

                    if uri:

                        result.append(uri)

                        print(
                            "[+] HYSTERIA:",
                            remark
                        )

        # Рекурсивно ищем вложенные объекты
        for value in obj.values():

            extract_configs(
                value,
                result
            )

    elif isinstance(obj, list):

        for value in obj:

            extract_configs(
                value,
                result
            )


# ============================================================
# BASE64 DECODER
# ============================================================

def decode_subscription(text):

    text = str(text or "").strip()

    # Удаляем whitespace
    text = re.sub(
        r"\s+",
        "",
        text
    )

    # JSON string
    if (
        text.startswith('"')
        and text.endswith('"')
    ):
        try:
            text = json.loads(text)
        except Exception:
            pass

    # Если вдруг сервер уже вернул JSON
    if text.startswith("{") or text.startswith("["):
        return text

    # Base64
    try:

        padded = (
            text
            + "=" * (-len(text) % 4)
        )

        raw = base64.b64decode(
            padded,
            validate=False
        )

    except Exception as e:

        print(
            "[-] Base64 error:",
            e
        )

        return None

    decoded = raw.decode(
        "utf-8",
        errors="ignore"
    ).strip()

    return decoded


# ============================================================
# GIST
# ============================================================

def save_to_gist(content):

    if not MY_TOKEN:

        print(
            "[-] MY_TOKEN не задан — Gist пропущен"
        )

        return

    headers = {
        "Authorization": f"token {MY_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
    }

    payload = {
        "description": GIST_DESCRIPTION,
        "public": False,
        "files": {
            GIST_FILENAME: {
                "content": content
            }
        }
    }

    try:

        if GIST_ID:

            url = (
                f"https://api.github.com/"
                f"gists/{GIST_ID}"
            )

            print(
                "[*] Обновляем Gist..."
            )

            resp = requests.patch(
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
                "[*] Создаём Gist..."
            )

            resp = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30
            )

    except Exception as e:

        print(
            "[-] Ошибка GitHub:",
            e
        )

        return

    if resp.status_code in {200, 201}:

        try:
            data = resp.json()
        except Exception:
            data = {}

        print(
            "[+] Gist успешно сохранён"
        )

        print(
            "[+] Gist:",
            data.get("html_url")
        )

        if not GIST_ID:

            print(
                "[!] Новый GIST_ID:",
                data.get("id")
            )

    else:

        print(
            "[-] GitHub HTTP:",
            resp.status_code
        )

        print(
            resp.text[:3000]
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 50)
    print("       BoSVPN CONFIG EXTRACTOR")
    print("=" * 50)

    session = requests.Session()

    session.headers.update({
        "User-Agent":
            "Mozilla/5.0 (Android 13; Mobile)",
        "Content-Type":
            "application/json",
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

    print("[*] Email:", email)
    print("[*] HWID:", hwid)

    # ========================================================
    # LOGIN
    # ========================================================

    print("\n[*] LOGIN...")

    try:

        resp = session.post(
            f"{BASE_URL}/api/auth/login",
            json={
                "email": email,
                "clientId": client_id,
                "hwid": hwid,
            },
            timeout=30
        )

    except Exception as e:

        print(
            "[-] LOGIN error:",
            e
        )

        return 1

    print(
        "[+] Login HTTP:",
        resp.status_code
    )

    if resp.status_code != 200:

        print(
            resp.text[:3000]
        )

        return 1

    try:

        data = resp.json()

    except Exception as e:

        print(
            "[-] LOGIN JSON error:",
            e
        )

        print(
            resp.text[:3000]
        )

        return 1

    if "accessToken" not in data:

        print(
            "[-] accessToken отсутствует"
        )

        print(
            json.dumps(
                data,
                ensure_ascii=False,
                indent=2
            )[:5000]
        )

        return 1

    print(
        "[+] Авторизация успешна"
    )

    # ========================================================
    # SUBSCRIPTION URL
    # ========================================================

    try:

        sub_api_url = (
            data
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

        return 1

    print(
        "\n[+] Subscription URL:"
    )

    print(
        sub_api_url
    )

    # ========================================================
    # SUB ID
    # ========================================================

    match = re.search(
        r"/api/sub/([^/]+)/",
        sub_api_url
    )

    if not match:

        print(
            "[-] Не удалось получить ID подписки"
        )

        return 1

    sub_id = match.group(1)

    real_sub_url = (
        f"https://access.bosx.net/"
        f"subb/{sub_id}"
    )

    print(
        "\n[+] Subscription endpoint:"
    )

    print(
        real_sub_url
    )

    # ========================================================
    # SUBSCRIPTION
    # ========================================================

    print(
        "\n[*] Получаем конфигурации..."
    )

    try:

        config_resp = session.get(
            real_sub_url,
            headers={
                "User-Agent":
                    "okhttp/4.12.0",
                "X-HWID":
                    hwid,
                "Accept":
                    "*/*",

                # Не просим br, чтобы не зависеть
                # от наличия brotli в runner.
                "Accept-Encoding":
                    "gzip, deflate",
            },
            timeout=30
        )

    except Exception as e:

        print(
            "[-] Subscription error:",
            e
        )

        return 1

    print(
        "[+] Subscription HTTP:",
        config_resp.status_code
    )

    print(
        "[+] Content-Type:",
        config_resp.headers.get(
            "Content-Type"
        )
    )

    print(
        "[+] Content-Encoding:",
        config_resp.headers.get(
            "Content-Encoding"
        )
    )

    if config_resp.headers.get(
        "X-Hwid-Not-Supported"
    ):

        print(
            "[-] HWID не принят"
        )

        return 1

    if config_resp.status_code != 200:

        print(
            "[-] Subscription error:"
        )

        print(
            config_resp.text[:3000]
        )

        return 1

    # ========================================================
    # BODY
    # ========================================================

    body = config_resp.text.strip()

    print(
        "[+] Получено:",
        len(body),
        "символов"
    )

    # ========================================================
    # BASE64
    # ========================================================

    print(
        "\n[*] Декодируем Base64..."
    )

    decoded = decode_subscription(
        body
    )

    if not decoded:

        print(
            "[-] Декодирование не удалось"
        )

        return 1

    print(
        "[+] После Base64:",
        len(decoded),
        "символов"
    )

    # ========================================================
    # SAVE DECODED
    # ========================================================

    with open(
        "subscription_decoded.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(decoded)

    print(
        "[+] subscription_decoded.txt сохранён"
    )

    # ========================================================
    # JSON
    # ========================================================

    try:

        json_data = json.loads(
            decoded
        )

    except Exception as e:

        print(
            "[-] JSON error:",
            e
        )

        print(
            decoded[:3000]
        )

        return 1

    print(
        "[+] JSON успешно разобран"
    )

    # ========================================================
    # EXTRACT
    # ========================================================

    print("\n" + "=" * 50)
    print("          EXTRACT CONFIGS")
    print("=" * 50)

    configs = []

    extract_configs(
        json_data,
        configs
    )

    # ========================================================
    # REMOVE DUPLICATES
    # ========================================================

    unique_configs = []
    seen = set()

    for config in configs:

        if config in seen:
            continue

        seen.add(config)
        unique_configs.append(config)

    configs = unique_configs

    # ========================================================
    # STATISTICS
    # ========================================================

    vless_count = sum(
        1
        for x in configs
        if x.startswith("vless://")
    )

    hysteria_count = sum(
        1
        for x in configs
        if x.startswith("hysteria2://")
    )

    print("\n" + "=" * 50)
    print("              РЕЗУЛЬТАТ")
    print("=" * 50)

    print(
        "[+] VLESS:",
        vless_count
    )

    print(
        "[+] Hysteria2:",
        hysteria_count
    )

    print(
        "[+] Всего:",
        len(configs)
    )

    # ========================================================
    # SAVE ALL
    # ========================================================

    final_content = "\n".join(
        configs
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        if final_content:
            f.write(final_content)
            f.write("\n")

    print(
        f"\n[+] {OUTPUT_FILE} создан"
    )

    print(
        "[+] Размер:",
        os.path.getsize(OUTPUT_FILE),
        "bytes"
    )

    # ========================================================
    # PRINT LINKS
    # ========================================================

    print("\n" + "=" * 50)
    print("             CONFIG LINKS")
    print("=" * 50)

    for i, config in enumerate(
        configs,
        1
    ):

        print(
            f"\n[{i}]"
        )

        print(
            config
        )

    # ========================================================
    # GIST
    # ========================================================

    save_to_gist(
        final_content
    )

    print("\n" + "=" * 50)
    print("                 DONE")
    print("=" * 50)

    return 0


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    raise SystemExit(
        main()
    )
