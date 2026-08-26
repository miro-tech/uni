#!/usr/bin/env python3

import base64
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
    quote,
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

# Новый SNI
SNI = "rbc.ru"


# ============================================================
# ALPN
# ============================================================

REMOVE_ALPN = {
    "h2",
    "http/1.1",
}


# ============================================================
# DNS CACHE
# ============================================================

DNS_CACHE = {}


def is_ipv4(value):
    return bool(
        re.fullmatch(
            r"\d{1,3}(?:\.\d{1,3}){3}",
            str(value),
        )
    )


def resolve_host(host):
    """
    DNS hostname -> IPv4.
    Если уже IP — возвращает его без изменений.
    """

    host = str(host).strip()

    if not host:
        return host

    if is_ipv4(host):
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
# ALPN CLEAN
# ============================================================

def clean_alpn(value):
    """
    Например:

        h2
        http/1.1
        h2,http/1.1
        http/1.1,h2

    полностью удаляются.

    Если есть что-то ещё, например:

        h2,h3

    получится:

        h3
    """

    if value is None:
        return None

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
# URL PROCESSOR
# ============================================================

def process_uri(uri):
    """
    Обрабатывает уже готовую VLESS/Hysteria URI.

    Делает:

    1. hostname -> IPv4
    2. sni -> rbc.ru
    3. удаляет h2/http1.1 из ALPN
    """

    uri = uri.strip()

    if not uri:
        return None

    if not (
        uri.startswith("vless://")
        or uri.startswith("hysteria://")
        or uri.startswith("hysteria2://")
    ):
        return None

    try:
        parts = urlsplit(uri)

    except Exception as e:

        print(
            "[!] URL parse error:",
            e
        )

        return None

    # ========================================================
    # SERVER
    # ========================================================

    netloc = parts.netloc

    # --------------------------------------------------------
    # userinfo@host:port
    # --------------------------------------------------------

    if "@" in netloc:

        userinfo, server = netloc.rsplit("@", 1)

    else:

        userinfo = ""
        server = netloc

    # --------------------------------------------------------
    # IPv4 / hostname
    # --------------------------------------------------------

    host = ""
    port = ""

    if server.startswith("["):

        # IPv6
        m = re.match(
            r"^\[([^\]]+)\](?::(\d+))?$",
            server,
        )

        if m:

            host = m.group(1)
            port = m.group(2) or ""

    else:

        m = re.match(
            r"^([^:]+)(?::(\d+))?$",
            server,
        )

        if m:

            host = m.group(1)
            port = m.group(2) or ""

    if not host:

        print(
            "[!] Не удалось определить host:",
            uri[:150]
        )

        return None

    # ========================================================
    # DNS
    # ========================================================

    if not is_ipv4(host):

        new_host = resolve_host(host)

    else:

        new_host = host

    # Если DNS не сработал — оставляем hostname.
    # Это лучше, чем потерять конфиг.
    host_for_uri = new_host

    # ========================================================
    # REBUILD NETLOC
    # ========================================================

    if userinfo:

        new_netloc = (
            f"{userinfo}@{host_for_uri}"
        )

    else:

        new_netloc = host_for_uri

    if port:

        new_netloc += f":{port}"

    # ========================================================
    # QUERY
    # ========================================================

    params = parse_qsl(
        parts.query,
        keep_blank_values=True,
    )

    new_params = []

    sni_added = False

    for key, value in params:

        key_lower = key.lower()

        # ----------------------------------------------------
        # SNI
        # ----------------------------------------------------

        if key_lower == "sni":

            if not sni_added:

                new_params.append(
                    ("sni", SNI)
                )

                sni_added = True

            continue

        # ----------------------------------------------------
        # ALPN
        # ----------------------------------------------------

        if key_lower == "alpn":

            new_alpn = clean_alpn(value)

            if new_alpn:

                new_params.append(
                    (
                        "alpn",
                        new_alpn,
                    )
                )

            continue

        # ----------------------------------------------------
        # Остальное оставляем
        # ----------------------------------------------------

        new_params.append(
            (
                key,
                value,
            )
        )

    # ========================================================
    # Если SNI отсутствовал
    # ========================================================

    if not sni_added:

        new_params.append(
            (
                "sni",
                SNI,
            )
        )

    # ========================================================
    # QUERY
    # ========================================================

    new_query = urlencode(
        new_params,
        doseq=True,
    )

    # ========================================================
    # FINAL URI
    # ========================================================

    result = urlunsplit(
        (
            parts.scheme,
            new_netloc,
            parts.path,
            new_query,
            parts.fragment,
        )
    )

    return result


# ============================================================
# DECODE BASE64
# ============================================================

def decode_subscription(text):
    """
    Декодирует Base64 подписку.

    Возвращает обычный текст,
    внутри которого находятся готовые URI.
    """

    text = text.strip()

    # Убираем пробелы и переносы
    text = re.sub(
        r"\s+",
        "",
        text,
    )

    # Иногда сервер возвращает JSON string
    if (
        text.startswith('"')
        and text.endswith('"')
    ):

        try:

            import json

            text = json.loads(text)

        except Exception:
            pass

    # ========================================================
    # BASE64
    # ========================================================

    try:

        padded = (
            text
            + "=" * (-len(text) % 4)
        )

        raw = base64.b64decode(
            padded,
            validate=False,
        )

    except Exception as e:

        print(
            "[-] Base64 error:",
            e,
        )

        return None

    # ========================================================
    # UTF-8
    # ========================================================

    decoded = raw.decode(
        "utf-8",
        errors="ignore",
    ).strip()

    return decoded


# ============================================================
# EXTRACT URI
# ============================================================

def extract_uris(decoded):
    """
    Ищет в декодированной подписке:

        vless://
        hysteria://
        hysteria2://

    """

    result = []

    # Разбиваем по строкам
    for line in decoded.splitlines():

        line = line.strip()

        if not line:
            continue

        # ----------------------------------------------------
        # Иногда несколько URI могут находиться в одной строке
        # ----------------------------------------------------

        matches = re.findall(
            r"(?:vless|hysteria2?|hysteria)://\S+",
            line,
            flags=re.IGNORECASE,
        )

        for match in matches:

            # Убираем возможные лишние символы
            match = match.strip()

            match = match.rstrip(
                "\r\n"
            )

            result.append(
                match
            )

    # ========================================================
    # Если splitlines ничего не нашёл
    # ========================================================

    if not result:

        matches = re.findall(
            r"(?:vless|hysteria2?|hysteria)://\S+",
            decoded,
            flags=re.IGNORECASE,
        )

        result.extend(
            matches
        )

    return result


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

    # ========================================================
    # UPDATE
    # ========================================================

    if GIST_ID:

        url = (
            "https://api.github.com/gists/"
            + GIST_ID
        )

        print(
            "\n[*] Обновляем Gist..."
        )

        try:

            resp = requests.patch(
                url,
                json=payload,
                headers=headers,
                timeout=30,
            )

        except Exception as e:

            print(
                "[-] Gist error:",
                e
            )

            return

    # ========================================================
    # CREATE
    # ========================================================

    else:

        url = (
            "https://api.github.com/gists"
        )

        print(
            "\n[*] Создаём Gist..."
        )

        try:

            resp = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30,
            )

        except Exception as e:

            print(
                "[-] Gist error:",
                e
            )

            return

    # ========================================================
    # RESULT
    # ========================================================

    if resp.status_code in {
        200,
        201,
    }:

        data = resp.json()

        print(
            "[+] Gist успешно сохранён"
        )

        print(
            "[+] Gist:",
            data.get("html_url")
        )

        if not GIST_ID:

            print(
                "[!] GIST_ID:"
            )

            print(
                data.get("id")
            )

    else:

        print(
            "[-] GitHub Gist error:",
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
                k=10,
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
            "[-] JSON LOGIN error:",
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
            "[-] subscriptionUrl отсутствует:",
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
        sub_api_url,
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

            },

            timeout=30,
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
            "[-] Ошибка subscription:"
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
            "[-] Не удалось декодировать Base64"
        )

        return 1

    print(
        "[+] После Base64:",
        len(decoded),
        "символов"
    )

    # ========================================================
    # SAVE RAW
    # ========================================================

    with open(
        "subscription_decoded.txt",
        "w",
        encoding="utf-8",
    ) as f:

        f.write(decoded)

    print(
        "[+] subscription_decoded.txt сохранён"
    )

    # ========================================================
    # EXTRACT URI
    # ========================================================

    print(
        "\n[*] Ищем VLESS/Hysteria..."
    )

    raw_uris = extract_uris(
        decoded
    )

    print(
        "[+] Найдено URI:",
        len(raw_uris)
    )

    if not raw_uris:

        print(
            "[-] Не найдено ни одного VLESS/Hysteria URI"
        )

        print(
            "\nПервые данные после Base64:"
        )

        print(
            decoded[:5000]
        )

        return 1

    # ========================================================
    # PROCESS
    # ========================================================

    configs = []

    for uri in raw_uris:

        processed = process_uri(
            uri
        )

        if not processed:
            continue

        configs.append(
            processed
        )

    # ========================================================
    # REMOVE DUPLICATES
    # ========================================================

    unique_configs = []

    seen = set()

    for config in configs:

        if config in seen:
            continue

        seen.add(
            config
        )

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
        if x.startswith(
            "vless://"
        )
    )

    hysteria_count = sum(
        1
        for x in configs
        if (
            x.startswith("hysteria://")
            or
            x.startswith("hysteria2://")
        )
    )

    print(
        "\n=================================================="
    )

    print(
        "                  РЕЗУЛЬТАТ"
    )

    print(
        "=================================================="
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
    # CHECK
    # ========================================================

    if not configs:

        print(
            "[-] После обработки не осталось конфигов"
        )

        return 1

    # ========================================================
    # FINAL CONTENT
    # ========================================================

    final_content = "\n".join(
        configs
    ) + "\n"

    # ========================================================
    # SAVE CONFIGS.TXT
    # ========================================================

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        f.write(
            final_content
        )

    print(
        "\n[+] configs.txt СОЗДАН"
    )

    print(
        "[+] Размер:",
        len(final_content),
        "байт"
    )

    # ========================================================
    # PRINT
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

    for i, config in enumerate(
        configs,
        1,
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

    # ========================================================
    # DONE
    # ========================================================

    print(
        "\n=================================================="
    )

    print(
        "                    DONE"
    )

    print(
        "=================================================="
    )

    return 0


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )
