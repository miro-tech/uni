import base64
import os
import random
import re
import socket
import string
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests


BASE_URL = "https://bos.tg"

# GitHub Gist
MY_TOKEN = os.getenv("MY_TOKEN")
GIST_ID = os.getenv("GIST_ID")
GIST_FILENAME = "bosvpn.txt"
GIST_DESCRIPTION = "Auto-updated BoSVPN configs"


REMOVE_ALPN = {
    "h2",
    "http/1.1",
    "h2,http/1.1",
    "http/1.1,h2",
}


def process_configs(raw_text):
    """
    Обрабатывает VLESS-конфигурации:
    - DNS hostname -> IPv4
    - удаляет определённые ALPN
    - заменяет SNI на rbc.ru
    """

    cache = {}
    lines = raw_text.splitlines()
    result = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if not line.startswith("vless://"):
            result.append(line)
            continue

        try:
            parts = urlsplit(line)
            netloc = parts.netloc

            match = re.match(r"(.+@)([^:]+)(:\d+)", netloc)

            if match:
                prefix, host, port = match.groups()

                # Если host не IPv4
                if not re.fullmatch(
                    r"\d{1,3}(?:\.\d{1,3}){3}",
                    host
                ):
                    if host not in cache:
                        try:
                            cache[host] = socket.gethostbyname(host)
                            print(
                                f"[DNS] {host} -> {cache[host]}"
                            )
                        except Exception:
                            print(
                                f"[DNS] Не удалось разрешить {host}"
                            )
                            cache[host] = host

                    netloc = prefix + cache[host] + port

            params = parse_qsl(
                parts.query,
                keep_blank_values=True
            )

            new_params = []

            for key, value in params:

                # Удаляем ALPN
                if key == "alpn" and value in REMOVE_ALPN:
                    continue

                # Меняем SNI
                if key == "sni":
                    value = "rbc.ru"

                new_params.append((key, value))

            new_query = urlencode(new_params)

            new_link = urlunsplit(
                (
                    parts.scheme,
                    netloc,
                    parts.path,
                    new_query,
                    parts.fragment,
                )
            )

            result.append(new_link)

        except Exception as e:
            print(f"[-] Ошибка обработки строки: {e}")

            # Не теряем исходную строку
            result.append(line)

    return result


def save_to_gist(content):
    """Создаёт или обновляет GitHub Gist."""

    if not MY_TOKEN:
        print(
            "[-] Ошибка: переменная окружения MY_TOKEN "
            "не задана!"
        )
        return False

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
        },
    }

    try:
        if GIST_ID:
            url = f"https://api.github.com/gists/{GIST_ID}"

            response = requests.patch(
                url,
                json=payload,
                headers=headers,
                timeout=30,
            )
        else:
            url = "https://api.github.com/gists"

            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30,
            )

    except requests.RequestException as e:
        print(f"[-] Ошибка GitHub API: {e}")
        return False

    if response.status_code in (200, 201):
        data = response.json()

        print("[+] Gist успешно сохранён!")

        if data.get("html_url"):
            print(f"[+] Gist: {data['html_url']}")

        if not GIST_ID and data.get("id"):
            print(
                f"[!] Новый GIST_ID: {data['id']}"
            )

        return True

    print(
        f"[-] Ошибка сохранения Gist: "
        f"HTTP {response.status_code}"
    )
    print(response.text)

    return False


def main():

    print("=" * 60)
    print("BoSVPN config updater")
    print("=" * 60)

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Android 13; Mobile)",
            "Content-Type": "application/json",
        }
    )

    # ---------------------------------------------------------
    # Генерируем данные клиента
    # ---------------------------------------------------------

    email = (
        "".join(
            random.choices(
                string.ascii_lowercase + string.digits,
                k=10,
            )
        )
        + "@gmail.com"
    )

    client_id = str(uuid.uuid4())
    hwid = str(uuid.uuid4())

    print(f"[*] Email: {email}")
    print(f"[*] HWID: {hwid}")

    # ---------------------------------------------------------
    # Login
    # ---------------------------------------------------------

    try:
        response = session.post(
            f"{BASE_URL}/api/auth/login",
            json={
                "email": email,
                "clientId": client_id,
                "hwid": hwid,
            },
            timeout=30,
        )
    except requests.RequestException as e:
        print(f"[-] Ошибка login: {e}")
        return 1

    print(
        f"[*] Login HTTP: {response.status_code}"
    )

    if response.status_code != 200:
        print("[-] Ошибка авторизации:")
        print(response.text)
        return 1

    try:
        data = response.json()
    except ValueError:
        print("[-] Login вернул не JSON:")
        print(response.text[:1000])
        return 1

    if "accessToken" not in data:
        print("[-] accessToken отсутствует")
        print(data)
        return 1

    # ---------------------------------------------------------
    # Получаем subscription URL
    # ---------------------------------------------------------

    try:
        sub_api_url = (
            data["user"]
            ["access"]
            ["premium"]
            ["subscriptionUrl"]
        )
    except (KeyError, TypeError):
        print(
            "[-] Не найден subscriptionUrl"
        )
        print(data)
        return 1

    print(
        f"[+] Subscription URL: {sub_api_url}"
    )

    # Извлекаем ID подписки
    try:
        sub_id = sub_api_url.rstrip("/").split("/")[-1]
    except Exception as e:
        print(
            f"[-] Не удалось получить subscription ID: {e}"
        )
        return 1

    real_sub_url = (
        f"https://access.bosx.net/subb/{sub_id}"
    )

    print(
        f"[+] Subscription endpoint: {real_sub_url}"
    )

    # ---------------------------------------------------------
    # Получаем конфигурации
    # ---------------------------------------------------------

    try:
        config_response = session.get(
            real_sub_url,
            headers={
                "User-Agent": "okhttp/4.12.0",
                "X-HWID": hwid,
            },
            timeout=30,
        )
    except requests.RequestException as e:
        print(
            f"[-] Ошибка получения конфигураций: {e}"
        )
        return 1

    print(
        f"[*] Subscription HTTP: "
        f"{config_response.status_code}"
    )

    if config_response.status_code != 200:
        print(
            "[-] Сервер подписки вернул ошибку:"
        )
        print(config_response.text[:2000])
        return 1

    if config_response.headers.get(
        "X-Hwid-Not-Supported"
    ):
        print("[-] HWID не принят")
        return 1

    # ---------------------------------------------------------
    # Base64 decode
    # ---------------------------------------------------------

    encoded = config_response.text.strip()

    if not encoded:
        print("[-] Ответ подписки пустой")
        return 1

    try:
        configs_raw = base64.b64decode(
            encoded
        ).decode(
            "utf-8",
            errors="ignore",
        )

    except Exception as e:
        print(
            f"[-] Ошибка Base64 decode: {e}"
        )
        return 1

    if not configs_raw.strip():
        print(
            "[-] После Base64 decode "
            "конфигурации пустые"
        )
        return 1

    print(
        f"[+] Получено данных: "
        f"{len(configs_raw)} байт"
    )

    # ---------------------------------------------------------
    # Обработка конфигураций
    # ---------------------------------------------------------

    processed_lines = process_configs(
        configs_raw
    )

    final_content = "\n".join(
        processed_lines
    )

    # Добавляем завершающий перенос строки
    if final_content:
        final_content += "\n"

    count = sum(
        1
        for line in processed_lines
        if line.startswith("vless://")
    )

    print(
        f"[+] Обработано VLESS серверов: {count}"
    )

    # ---------------------------------------------------------
    # Сохраняем локальный configs.txt
    # ---------------------------------------------------------

    try:
        with open(
            "configs.txt",
            "w",
            encoding="utf-8",
        ) as file:
            file.write(final_content)

    except OSError as e:
        print(
            f"[-] Не удалось создать configs.txt: {e}"
        )
        return 1

    print(
        "[+] configs.txt успешно сохранён"
    )

    # Проверка файла
    try:
        file_size = os.path.getsize(
            "configs.txt"
        )

        print(
            f"[+] Размер configs.txt: "
            f"{file_size} байт"
        )

    except OSError:
        print(
            "[-] Не удалось проверить configs.txt"
        )
        return 1

    if file_size == 0:
        print(
            "[-] configs.txt пустой"
        )
        return 1

    # ---------------------------------------------------------
    # GitHub Gist
    # ---------------------------------------------------------

    save_to_gist(
        final_content
    )

    print("=" * 60)
    print("Готово")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
