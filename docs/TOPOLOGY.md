# Топологія й налаштування мережі

## Схема

```text
                 Kali Linux host
                       |
              Docker bridge: labnet
                 172.28.57.0/24
                       |
          +------------+-------------------+
          |                                |
    SERVER container                  CLIENT container
      172.28.57.10                      172.28.57.11
       TCP 8080 HTTP                     CLI client
       TCP 8443 HTTPS                    CA root: ca.crt
          |                                |
          +---------- authenticated TLS --+
          |
    SQLite + events.jsonl in local, untracked runtime/
```

`compose.yaml` має два окремі вузли, адреси закріплені за сервісами. Призначений лише навчальний subnet; на чужій машині може конфліктувати. Порти хостової ОС доступні лише через `127.0.0.1`.

## Два режими роботи

**Локальна демонстрація:** два HTTP(S)-слухачі, одна ОС/мережевий вузол. Цей режим забезпечує криптографічні інтеграційні тести, але **не підтверджує пункт 1 (два вузли)**.

**Docker Compose:** два різні контейнери `server` і `client`, різні адреси у Docker bridge; під час практики потрібно фактично запустити та задокументувати через `docker compose ps`, `hostname -i` усередині контейнерів, запити `client -> server`. Наявність YAML-файлу ще не є доказом роботи двох вузлів.

## TLS/сертифікати

1. `python tools/setup_lab.py init` створює локальний CA (самопідписаний) та підписує серверний сертифікат.
2. CA (`server/certs/ca.crt`) передається клієнту; приватний CA-ключ і TLS-ключ на клієнт **не монтуються**.
3. У SAN: DNS `localhost`, `server`; IP `127.0.0.1`, `172.28.57.10`.
4. Python `ssl.create_default_context(cafile=...)` перевіряє ланцюг довіри й SAN; власні TLS мінімум 1.2, рекомендовано TLS 1.3.
5. Контроль: `openssl verify -CAfile server/certs/ca.crt server/certs/server.crt` та тест із недовіреним CA, який відхиляє підключення.

```bash
openssl x509 -in server/certs/server.crt -noout -text | grep -A3 'Subject Alternative Name'
openssl verify -CAfile server/certs/ca.crt server/certs/server.crt
```

**Захист від витоку:** `ca.key`, `server.key`, `.env`, `runtime/` заборонені і Git, і Docker build context. Перед публікацією виконайте `git status --short` та `git ls-files`.
