#!/usr/bin/env python3

import base64
import json
import os
import random
import re
import socket
import string
import uuid

from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
    quote
)

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

SNI = "rbc.ru"

# ALPN, которые полностью удаляем
REMOVE_ALPN = {
    "h2",
    "http/1.1",
    "h2,http/1.1",
    "http/1.1,h2",
}


# ============================================================
# DNS CACHE
# ============================================================

DNS_CACHE = {}


def resolve_host(host):
    """
    DNS hostname -> IPv4.

    Если уже IP — возвращаем как есть.
    """

    if not host:
        return host

    # Уже IPv4
    if re.fullmatch(
        r"\d{1,3}(?:\.\d{1,3}){3}",
        host
    ):
        return host

    if host in DNS_CACHE:
        return DNS_CACHE[host]

    try:
        ip = socket.gethostbyname(host)

        DNS_CACHE[host] = ip

        print(
            f"[DNS] {host} -> {ip}"
        )

        return ip

    except Exception as e:

        print(
            f"[DNS] Не удалось разрешить {host}: {e}"
        )

        DNS_CACHE[host] = host

        return host


# ============================================================
# ALPN
# ============================================================

def clean_alpn(value):
    """
    Удаляет h2/http1.1.

    Если ALPN:
        h2
        http/1.1
        h2,http/1.1

    возвращает None.

    Остальные значения сохраняются.
    """

    if value is None:
        return None

    if isinstance(value, list):

        result = []

        for item in value:

            item = str(item).strip()

            if item.lower() in REMOVE_ALPN:
                continue

            result.append(item)

        if not result:
            return None

        return result

    value = str(value).strip()

    if value.lower() in REMOVE_ALPN:
        return None

    # На случай строки:
    # h2,http/1.1
    parts = [
        x.strip()
        for x in value.split(",")
    ]

    parts = [
        x for x in parts
        if x.lower() not in {
            "h2",
            "http/1.1"
        }
    ]

    if not parts:
        return None

    return ",".join(parts)


# ============================================================
# QUERY HELPERS
# ============================================================

def make_query(params):
    """
    Формирует URL query.

    urlencode автоматически делает:
        h2,http/1.1
        /
        пробелы

    безопасными для URL.
    """

    return urlencode(
        params,
        doseq=True
    )


# ============================================================
# VLESS
# ============================================================

def build_vless(outbound, remark=""):
    """
    Из VLESS outbound делает vless:// URI.
    """

    settings = outbound.get(
        "settings",
        {}
    )

    stream = outbound.get(
        "streamSettings",
        {}
    )

    # --------------------------------------------------------
    # SERVER
    # --------------------------------------------------------

    address = ""
    port = ""

    # Xray VLESS:
    #
    # settings.vnext[0].address
    # settings.vnext[0].port

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
            users = []

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

        users = (
            settings.get("vnext", [{}])[0].get(
                "users",
                []
            )
            if isinstance(
                settings.get("vnext", []),
                list
            )
            and settings.get("vnext")
            else []
        )

    if not users:

        print(
            "[-] VLESS: не найден users"
        )

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
        print(
            "[-] VLESS: не найден UUID"
        )
        return None

    # --------------------------------------------------------
    # DNS -> IP
    # --------------------------------------------------------

    ip = resolve_host(
        str(address)
    )

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

    # --------------------------------------------------------
    # TYPE
    # --------------------------------------------------------

    if network:
        params.append(
            ("type", network)
        )

    # --------------------------------------------------------
    # SECURITY
    # --------------------------------------------------------

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

    # Всегда меняем SNI
    if security == "tls":

        params.append(
            ("sni", SNI)
        )

        # fingerprint оставляем
        fingerprint = tls.get(
            "fingerprint"
        )

        if fingerprint:
            params.append(
                (
                    "fp",
                    str(fingerprint)
                )
            )

        # ALPN
        alpn = clean_alpn(
            tls.get("alpn")
        )

        if alpn:

            if isinstance(alpn, list):

                params.append(
                    (
                        "alpn",
                        ",".join(alpn)
                    )
                )

            else:

                params.append(
                    (
                        "alpn",
                        alpn
                    )
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
                    (
                        "path",
                        path
                    )
                )

            headers = ws.get(
                "headers",
                {}
            )

            if isinstance(headers, dict):

                host = headers.get(
                    "Host"
                )

                if host:
                    params.append(
                        (
                            "host",
                            host
                        )
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
                    (
                        "mode",
                        mode
                    )
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
                    (
                        "path",
                        path
                    )
                )

            host = xhttp.get(
                "host"
            )

            if host:
                params.append(
                    (
                        "host",
                        host
                    )
                )

    # --------------------------------------------------------
    # REALITY
    # --------------------------------------------------------

    reality = stream.get(
        "realitySettings"
    )

    if isinstance(reality, dict):

        # Если Reality — SNI тоже rbc.ru
        params.append(
            ("sni", SNI)
        )

        public_key = (
            reality.get("publicKey")
            or reality.get("pbk")
        )

        if public_key:

            params.append(
                (
                    "pbk",
                    public_key
                )
            )

        short_id = (
            reality.get("shortId")
            or reality.get("sid")
        )

        if short_id:

            params.append(
                (
                    "sid",
                    short_id
                )
            )

        spider_x = (
            reality.get("spiderX")
            or reality.get("spx")
        )

        if spider_x:

            params.append(
                (
                    "spx",
                    spider_x
                )
            )

        fingerprint = (
            reality.get("fingerprint")
        )

        if fingerprint:

            params.append(
                (
                    "fp",
                    fingerprint
                )
            )

    # --------------------------------------------------------
    # FLOW
    # --------------------------------------------------------

    flow = user.get(
        "flow"
    )

    if flow:

        params.append(
            (
                "flow",
                flow
            )
        )

    # --------------------------------------------------------
    # BUILD
    # --------------------------------------------------------

    query = make_query(
        params
    )

    fragment = quote(
        str(remark),
        safe=""
    )

    uri = (
        f"vless://"
        f"{uuid_value}@"
        f"{ip}:{port}"
        f"/?"
        f"{query}"
        f"#{fragment}"
    )

    return uri


# ============================================================
# HYSTERIA
# ============================================================

def build_hysteria(outbound, remark=""):
    """
    Hysteria -> hysteria2://
    """

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
    # ADDRESS / PORT
    # --------------------------------------------------------

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

    # Некоторые конфиги могут хранить
    # сервер в hysteriaSettings.

    hysteria_settings = stream.get(
        "hysteriaSettings",
        {}
    )

    if not isinstance(
        hysteria_settings,
        dict
    ):
        hysteria_settings = {}

    if not address:

        address = (
            hysteria_settings.get("address")
            or ""
        )

    if not port:

        port = (
            hysteria_settings.get("port")
            or ""
        )

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
    # DNS -> IP
    # --------------------------------------------------------

    ip = resolve_host(
        str(address)
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

    # SNI всегда rbc.ru
    params = [
        (
            "sni",
            SNI
        ),
        (
            "insecure",
            "0"
        )
    ]

    # --------------------------------------------------------
    # ALPN
    # --------------------------------------------------------

    alpn = clean_alpn(
        tls.get("alpn")
    )

    if alpn:

        if isinstance(alpn, list):

            params.append(
                (
                    "alpn",
                    ",".join(alpn)
                )
            )

        else:

            params.append(
                (
                    "alpn",
                    alpn
                )
            )

    # --------------------------------------------------------
    # OBFUSCATION
    # --------------------------------------------------------

    obfs = (
        hysteria_settings.get("obfs")
        or settings.get("obfs")
    )

    if obfs:

        params.append(
            (
                "obfs",
                str(obfs)
            )
        )

    # --------------------------------------------------------
    # BUILD
    # --------------------------------------------------------

    query = make_query(
        params
    )

    fragment = quote(
        str(remark),
        safe=""
    )

    uri = (
        f"hysteria2://"
        f"{quote(str(auth), safe='')}@"
        f"{ip}:{port}"
        f"/?"
        f"{query}"
        f"#{fragment}"
    )

    return uri


# ============================================================
# RECURSIVE JSON SCANNER
# ============================================================

def extract_configs(obj, result):
    """
    Рекурсивно ищет все outbounds.

    Поддерживает:
        vless
        hysteria
        hysteria2
    """

    if isinstance(obj, dict):

        # ----------------------------------------------------
        # OUTBOUNDS
        # ----------------------------------------------------

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

                # --------------------------------------------
                # VLESS
                # --------------------------------------------

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

                # --------------------------------------------
                # HYSTERIA
                # --------------------------------------------

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

        # ----------------------------------------------------
        # RECURSION
        # ----------------------------------------------------

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
# DECODE SUBSCRIPTION
# ============================================================

def decode_subscription(text):
    """
    Декодирует Base64 подписку.

    Поддерживает:
        обычный Base64
        Base64 с переносами
        padding
    """

    text = text.strip()

    # Убираем whitespace
    text = re.sub(
        r"\s+",
        "",
        text
    )

    # Иногда сервер может вернуть JSON-строку
    if (
        text.startswith('"')
        and text.endswith('"')
    ):
        try:
            text = json.loads(text)
        except Exception:
            pass

    # --------------------------------------------------------
    # BASE64
    # --------------------------------------------------------

    try:

        raw = base64.b64decode(
            text + "=" * (
                -len(text) % 4
            ),
            validate=False
        )

    except Exception as e:

        print(
            "[-] Base64 error:",
            e
        )

        return None

    # --------------------------------------------------------
    # UTF-8
    # --------------------------------------------------------

    decoded = raw.decode(
        "utf-8",
        errors="ignore"
    ).strip()

    return decoded


# ============================================================
# GITHUB GIST
# ============================================================

def save_to_gist(content):

    if not MY_TOKEN:

        print(
            "[-] Ошибка: MY_TOKEN "
            "не задан!"
        )

        return

    headers = {
        "Authorization":
            f"token {MY_TOKEN}",

        "Accept":
            "application/vnd.github.v3+json",

        "Content-Type":
            "application/json",
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
        },
    }

    # --------------------------------------------------------
    # UPDATE
    # --------------------------------------------------------

    if GIST_ID:

        url = (
            f"https://api.github.com/"
            f"gists/{GIST_ID}"
        )

        print(
            "\n[*] Обновляем существующий Gist..."
        )

        resp = requests.patch(
            url,
            json=payload,
            headers=headers,
            timeout=30,
        )

    # --------------------------------------------------------
    # CREATE
    # --------------------------------------------------------

    else:

        url = (
            "https://api.github.com/gists"
        )

        print(
            "\n[*] Создаём новый Gist..."
        )

        resp = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=30,
        )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    if resp.status_code in {
        200,
        201
    }:

        data = resp.json()

        print(
            "\n[+] Gist успешно сохранён!"
        )

        print(
            "[+] Gist:",
            data.get("html_url")
        )

        if not GIST_ID:

            print(
                "[!] GIST_ID для следующих "
                "запусков:"
            )

            print(
                data.get("id")
            )

    else:

        print(
            "\n[-] Ошибка GitHub:",
            resp.status_code
        )

        print(
            resp.text[:3000]
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "========================================"
    )

    print(
        "        BoSVPN CONFIG EXTRACTOR"
    )

    print(
        "========================================"
    )

    session = requests.Session()

    session.headers.update({

        "User-Agent":
            "Mozilla/5.0 "
            "(Android 13; Mobile)",

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

    print(
        "[*] Email:",
        email
    )

    print(
        "[*] HWID:",
        hwid
    )

    # ========================================================
    # LOGIN
    # ========================================================

    print(
        "\n[*] LOGIN..."
    )

    try:

        resp = session.post(

            f"{BASE_URL}/api/auth/login",

            json={

                "email":
                    email,

                "clientId":
                    client_id,

                "hwid":
                    hwid,
            },

            timeout=30,
        )

    except Exception as e:

        print(
            "[-] Ошибка LOGIN:",
            e
        )

        return

    print(
        "[+] Login HTTP:",
        resp.status_code
    )

    if resp.status_code != 200:

        print(
            resp.text[:3000]
        )

        return

    try:

        data = resp.json()

    except Exception as e:

        print(
            "[-] JSON LOGIN error:",
            e
        )

        print(
            resp.text[:3000]
        )

        return

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

        return

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
            "[-] Не найден subscriptionUrl:",
            e
        )

        return

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
            "[-] Не удалось получить "
            "ID подписки"
        )

        return

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
    # SUBSCRIPTION REQUEST
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

                "Accept-Encoding":
                    "gzip, deflate, br",
            },

            timeout=30,
        )

    except Exception as e:

        print(
            "[-] Ошибка subscription:",
            e
        )

        return

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

        return

    if config_resp.status_code != 200:

        print(
            "[-] Ошибка subscription:"
        )

        print(
            config_resp.text[:3000]
        )

        return

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
            "[-] Не удалось декодировать"
        )

        return

    print(
        "[+] После Base64:",
        len(decoded),
        "символов"
    )

    # ========================================================
    # SAVE RAW DECODED
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

        return

    print(
        "[+] JSON успешно разобран"
    )

    # ========================================================
    # EXTRACT
    # ========================================================

    print(
        "\n========================================"
    )

    print(
        "          EXTRACT CONFIGS"
    )

    print(
        "========================================"
    )

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

        unique_configs.append(
            config
        )

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

    print(
        "\n========================================"
    )

    print(
        "              РЕЗУЛЬТАТ"
    )

    print(
        "========================================"
    )

    print(
        "[+] VLESS:",
        vless_count
    )

    print(
        "[+] Hysteria:",
        hysteria_count
    )

    print(
        "[+] Всего:",
        len(configs)
    )

    # ========================================================
    # SAVE ALL CONFIGS
    # ========================================================

    final_content = "\n".join(
        configs
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            final_content
        )

        if configs:
            f.write("\n")

    print(
        "\n[+] Все конфиги сохранены:"
    )

    print(
        f"[+] {OUTPUT_FILE}"
    )

    # ========================================================
    # PRINT
    # ========================================================

    print(
        "\n========================================"
    )

    print(
        "             CONFIG LINKS"
    )

    print(
        "========================================"
    )

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

    print(
        "\n========================================"
    )

    print(
        "                 DONE"
    )

    print(
        "========================================"
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
