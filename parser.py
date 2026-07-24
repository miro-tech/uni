import base64
import os
import random
import re
import socket
import string
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import uuid
import requests

BASE_URL = "https://bos.tg"

# --- НАСТРОЙКИ GITHUB (через переменные окружения / секреты) ---
MY_TOKEN = os.getenv("MY_TOKEN")
GIST_ID = os.getenv("GIST_ID")
GIST_FILENAME = "bosvpn.txt"
GIST_DESCRIPTION = "Auto-updated BoSVPN configs"
# -------------------------------------------------------------

REMOVE_ALPN = {
    "h2",
    "http/1.1",
    "h2,http/1.1",
    "http/1.1,h2",
}


def process_configs(raw_text):
  """Обрабатывает VLESS конфигурации (DNS резолв, замена SNI, фильтрация ALPN)"""
  cache = {}
  lines = raw_text.splitlines()
  result = []

  for line in lines:
    line = line.strip()

    if not line.startswith("vless://"):
      result.append(line)
      continue

    parts = urlsplit(line)
    netloc = parts.netloc
    m = re.match(r"(.+@)([^:]+)(:\d+)", netloc)

    if m:
      prefix, host, port = m.groups()

      if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        if host not in cache:
          try:
            cache[host] = socket.gethostbyname(host)
            print(f"[DNS] {host} -> {cache[host]}")
          except Exception:
            cache[host] = host

        netloc = prefix + cache[host] + port

    params = parse_qsl(parts.query, keep_blank_values=True)
    new_params = []

    for k, v in params:
      if k == "alpn" and v in REMOVE_ALPN:
        continue

      if k == "sni":
        v = "rbc.ru"

      new_params.append((k, v))

    new_query = urlencode(new_params)

    result.append(
        urlunsplit(
            (parts.scheme, netloc, parts.path, new_query, parts.fragment)
        )
    )

  return result


def save_to_gist(content):
  """Сохраняет или обновляет Gist на GitHub"""
  if not GITHUB_TOKEN:
    print("[-] Ошибка: Переменная окружения GITHUB_TOKEN не задана!")
    return

  headers = {
      "Authorization": f"token {MY_TOKEN}",
      "Accept": "application/vnd.github.v3+json",
  }

  payload = {
      "description": GIST_DESCRIPTION,
      "public": False,
      "files": {GIST_FILENAME: {"content": content}},
  }

  if GIST_ID:
    url = f"https://api.github.com/gists/{GIST_ID}"
    resp = requests.patch(url, json=payload, headers=headers)
  else:
    url = "https://api.github.com/gists"
    resp = requests.post(url, json=payload, headers=headers)

  if resp.status_code in [200, 201]:
    data = resp.json()
    print(f"\n[+] Успешно сохранено в Gist!")
    print(f"[+] Ссылка на Gist: {data.get('html_url')}")
    if not GIST_ID:
      print(
          f"[!] Сохраните этот Gist ID для будущих обновлений: {data.get('id')}"
      )
  else:
    print(f"[-] Ошибка при сохранении в Gist: {resp.status_code}")
    print(resp.text)


def main():
  session = requests.Session()
  session.headers.update(
      {"User-Agent": "Mozilla/5.0 (Android 13; Mobile)", "Content-Type": "application/json"}
  )

  email = (
      "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
      + "@gmail.com"
  )
  client_id = str(uuid.uuid4())
  hwid = str(uuid.uuid4())

  print("[*] Email:", email)
  print("[*] HWID:", hwid)

  resp = session.post(
      f"{BASE_URL}/api/auth/login",
      json={"email": email, "clientId": client_id, "hwid": hwid},
  )

  if resp.status_code != 200:
    print("[-] Ошибка HTTP:", resp.status_code)
    return

  data = resp.json()

  if "accessToken" not in data:
    print("[-] Ошибка авторизации")
    print(data)
    return

  sub_api_url = data["user"]["access"]["premium"]["subscriptionUrl"]
  sub_id = sub_api_url.split("/")[5]
  real_sub_url = f"https://access.bosx.net/subb/{sub_id}"

  print("[+] Subscription URL получен")

  config_resp = session.get(
      real_sub_url, headers={"User-Agent": "okhttp/4.12.0", "X-HWID": hwid}
  )

  if config_resp.headers.get("X-Hwid-Not-Supported"):
    print("[-] HWID не принят")
    return

  try:
    configs_raw = base64.b64decode(config_resp.text.strip()).decode(
        "utf-8", errors="ignore"
    )
  except Exception as e:
    print("[-] Ошибка декодирования:", e)
    return

  processed_lines = process_configs(configs_raw)
  final_content = "\n".join(processed_lines)

  count = sum(1 for line in processed_lines if line.startswith("vless://"))
  print(f"[+] Обработано серверов: {count}")

  save_to_gist(final_content)


if __name__ == "__main__":
  main()
