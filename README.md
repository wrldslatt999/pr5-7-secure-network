# ПР №5–7. Розробка безпечних мережевих застосунків

**Виконавець:** Чучула Євгеній Андрійович  
**Дисципліна:** Прикладні аспекти програмування  
**Мова:** Python 3.11+; OpenSSL; Docker Compose (для двох окремих вузлів)  
**Дата підготовки проєкту:** 26.11.2026

Навчальна система SecureNetLab: клієнт — сервер, контрольована демонстрація HTTP, перевірюване HTTPS/TLS, автентифікація, JWT із завершенням терміну дії та відкликанням, ролі `user/admin`, TOTP-MFA, обмеження спроб, структуровані логи, статичне сканування та автоматичні тести.

> **Важливо:** це навчальна лабораторія, а не готовий до використання в інтернеті продукт. HTTP-порт потрібен лише для порівняння й не приймає облікових даних. Не відкривайте тестові порти в публічну мережу.

## Чим проєкт відрізняється від `додаток_пр_5-7.rar`

Використано надану викладачем структуру `server/`, `client/`, `tools/`, `.github/workflows`. У шаблоні були небезпечні налаштування (публічний CORS `*`, запасний JWT-секрет, MFA, що вмикалася без підтвердження OTP, сканери з `|| true`, а також початковий `users.json`). У цьому варіанті вони усунені. **FastAPI з рекомендаційного шаблону замінено на модулі стандартної бібліотеки Python** (`http.server`, `ssl`, `sqlite3`, `hashlib`, `hmac`), щоб проєкт можна було відтворити без завантаження сторонніх Python-пакетів. JWT і TOTP реалізовано для навчальної демонстрації; для production потрібні перевірені бібліотеки, аудит і окремий KMS.

## Швидка перевірка (Kali Linux, без Docker)

Потрібні `python3` (3.11+) та `openssl` (OpenSSL 3.x рекомендований).

```bash
cd ~/Downloads/PR5-7_Secure_Network_Chuchula
python3 tools/setup_lab.py init
python3 tools/setup_lab.py add-user --user alice --role user
python3 tools/setup_lab.py add-user --user admin --role admin
python3 -m unittest discover -s tests -v
python3 tools/security_scan.py
```

Паролі вводяться через `getpass`; на екрані вони не відображаються. Паролі повинні містити від 12 до 256 байтів UTF-8. Програма **не записує їх у вихідний код**.

Запуск сервера у **першому терміналі**:

```bash
bash scripts/start_server.sh
```

Сервер слухає тільки loopback: `http://127.0.0.1:8080` (демонстраційний) і `https://127.0.0.1:8443` (захищений). У **другому терміналі** виконайте:

```bash
python3 -m client.client echo --http --msg 'HTTP demo'
python3 -m client.client health
python3 -m client.client login --user alice
python3 -m client.client whoami
python3 -m client.client echo --msg 'TLS authenticated echo'
python3 -m client.client admin
# Очікуване HTTP 403: роль user не має адміністративних прав.
```

Авторизований токен локально зберігається у `runtime/client_session.json` (режим 0600, не потрапляє в git); CLI не показує його у stdout. Для входу адміністратора повторіть `login --user admin`, після чого `admin` поверне HTTP 200.

### MFA (TOTP)

```bash
python3 -m client.client login --user alice
python3 -m client.client mfa-setup --user alice
# URI відобразиться ЛИШЕ на екрані — не публікуйте його.
# Додайте його в TOTP authenticator (6 цифр / 30 секунд).
python3 -m client.client mfa-confirm
python3 -m client.client login --user alice --otp
python3 -m client.client whoami
```

Поки MFA не підтверджено через OTP, вона не активна. Після підтвердження попередні токени без ознаки MFA вже не дають доступу. Сервер відкидає повторне використання того самого OTP. `login --otp` безпечно запитує код, не записуючи його в історію shell.

### Демонстрація brute force та аналіз логів

```bash
python3 -m client.client brute-demo --user alice --attempts 7
# Очікується 429 після 5 спроб/60 секунд; не використовуйте чужі облікові записи.
python3 tools/analyze_logs.py --event rate.limit
python3 tools/analyze_logs.py --user alice --event auth.fail
```

Після brute-force демонстрації треба почекати завершення обмежувального вікна (60 с) до чергового входу під тим самим обліковим записом. Для токенів передбачено 900 с життя, перевірка HS256/`iss`/`aud`/`exp`/`nbf`/`jti`, відкликання на logout у SQLite.

### Вимірювання HTTP vs HTTPS

```bash
python3 -m client.bench --n 20 --sizes 16 1024 2048 --out benchmarks
```

Дані автоматично записуються у `benchmarks/results.csv`, `.json`, `.md`. Бенчмарк на **одній ОС** порівнює два локальні слухачі: кожен запит відкриває окреме TCP/TLS-з'єднання, тому показник HTTPS містить накладні витрати TLS handshake. Уже включені результати отримані в окремому Linux-середовищі під час підготовки проєкту. Для точних результатів **на вашій Kali** повторіть команду та збережіть окремий коміт.

## Два ізольовані вузли в Docker Compose — завдання 1

Спочатку виконайте `setup_lab.py init` і створіть хоча б один обліковий запис на **хостовій Kali** (команди вище). Після цього:

```bash
docker compose up -d --build
docker compose ps
docker compose exec server hostname -i
docker compose exec client hostname -i
docker compose exec client python -m client.client echo --http --msg 'from client container'
docker compose exec client python -m client.client health
docker compose exec client python -m client.client login --user alice
docker compose exec client python -m client.client whoami
```

Статичні IP задано у `compose.yaml`:

| Роль | IPv4 | TCP | Призначення |
|---|---|---|---|
| `server` | `172.28.57.10` | 8080 | Тільки plaintext echo / health |
| `server` | `172.28.57.10` | 8443 | HTTPS, JWT, ролі, MFA |
| `client` | `172.28.57.11` | — | CLI, TLS trust anchor `ca.crt` |

Клієнт перевіряє підпис і DNS SAN `server` через локальний `ca.crt`; **`verify=False` немає**. Назовні порти опубліковані тільки як `127.0.0.1:8080` та `127.0.0.1:8443`. Docker Compose тут — опис відтворюваної топології: **поки користувач не запустить його у своїй Kali, фактичне розгортання двох контейнерів ще не підтверджене**. Якщо subnet вже зайнятий — змініть його та відповідний SAN перед новою генерацією сертифікатів.

Вимкнення контейнерів: `docker compose down`. Додавайте скриншоти `docker compose ps`, обох IP та HTTPS-відповіді до підтвердження розгортання.

## Перевірки та структура

```bash
python3 -m unittest discover -s tests -v
python3 tools/security_scan.py
```

- `server/app.py`: HTTP(S) JSON API, відмова автентифікації без TLS, ACL;
- `server/security.py`: scrypt, обмежений HS256 JWT, TOTP;
- `server/storage.py`: SQLite-облікові записи, revocation, MFA стан;
- `server/ratelimit.py`: rate limiting із потоковою синхронізацією;
- `server/logger_setup.py`: структурований JSONL журнал без секретів;
- `client/client.py`: TLS-клієнт, безпечний ввід паролів і OTP;
- `client/bench.py`: фактичні виміри медіани/P95/req/s;
- `tools/setup_lab.py`: створення `.env`, CA, TLS сертифіката та користувачів;
- `tools/analyze_logs.py`: фільтр журналів за подією, користувачем, датою;
- `tools/security_scan.py`: обов'язкова статична перевірка;
- `.github/workflows/security.yml`: матриця Python 3.11/3.12, tests + SAST;
- `tests/test_security.py`: юніт- і мережеві TLS-тести;
- `docs/REPORT.md`: структурований звіт за всіма 10 завданнями.

**Жодного секрету, приватного ключа або бази користувачів не треба комітити.** Це закріплено `.gitignore` і `.dockerignore`.

## GitHub та Moodle

Після локальної перевірки на Kali:

```bash
bash scripts/publish-github.sh
```

Скрипт запитає підтвердження, створить **приватний** репозиторій `wrldslatt999/pr5-7-secure-network` через GitHub CLI та завантажить код. Далі перевірте GitHub Actions. Для викладача відкрийте доступ до репозиторію або зробіть його Public після перевірки наявності секретів.

**Додаткова документація:** [звіт](docs/REPORT.md), [топологія](docs/TOPOLOGY.md), [безпека й обмеження](docs/SECURITY.md), [протокол тестів](docs/VERIFICATION.md), [аналіз логів](docs/LOG_ANALYSIS.md), [бенчмарки](benchmarks/results.md).

**Джерела:** [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [OWASP MFA](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html), [Python SSL](https://docs.python.org/3/library/ssl.html), [Python urllib](https://docs.python.org/3/library/urllib.request.html), [RFC 6238 TOTP](https://www.rfc-editor.org/rfc/rfc6238), [RFC 7519 JWT](https://www.rfc-editor.org/rfc/rfc7519), [Docker Compose network documentation](https://docs.docker.com/compose/how-tos/networking/).
