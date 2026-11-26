# HTTP проти HTTPS: виміри

Дата UTC: 2026-11-26T19:09:08.361558+00:00
Python: 3.14.10
ОС: Linux-7.2.15+kali-amd64-x86_64-with-glibc2.43
Топологія: local loopback; separate HTTP/HTTPS listeners, not Docker
Методика: new connection per request (TLS handshake included), sequential requests, no auth, verified CA, per-request response equality

| Протокол | Дані (байти) | Запитів | Медіана, мс | P95, мс | Запитів/с |
|---|---:|---:|---:|---:|---:|
| HTTP | 16 | 10 | 1.2797 | 1.4825 | 769.18 |
| HTTPS | 16 | 10 | 6.8862 | 7.7278 | 142.04 |
| HTTP | 1024 | 10 | 1.0879 | 1.6203 | 844.43 |
| HTTPS | 1024 | 10 | 7.1935 | 8.4757 | 136.33 |
| HTTP | 2048 | 10 | 1.3675 | 2.0396 | 687.01 |
| HTTPS | 2048 | 10 | 6.8588 | 7.2332 | 147.84 |

Застереження: час містить створення TCP-з’єднання і TLS handshake; це не лише вартість криптографії. Значення залежать від платформи.
