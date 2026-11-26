# Журналювання та аналіз подій

Події автоматично записуються до `runtime/events.jsonl`. Кожен запис має UTC timestamp, тип, за наявності — user, ip, path, status і elapsed_ms. Токени, OTP та паролі у лог **не потрапляють**. `runtime/` виключено з Git та Docker-образу.

## Фільтрація

```bash
python3 tools/analyze_logs.py
python3 tools/analyze_logs.py --event auth.fail
python3 tools/analyze_logs.py --event rate.limit
python3 tools/analyze_logs.py --user alice
python3 tools/analyze_logs.py --user alice --since '2026-11-26T00:00:00+00:00'
python3 tools/analyze_logs.py --until '2026-11-27T00:00:00+00:00'
```

Приклад типів подій: `auth.ok`, `auth.fail`, `auth.mfa.fail`, `auth.mfa.setup`, `auth.mfa.enabled`, `auth.forbidden`, `auth.token.invalid`, `auth.logout`, `rate.limit`, `http.request`.

## Детекція

- Збільшення `auth.fail` для одного користувача: неправильні паролі, парольний перебір.
- `rate.limit` після кількох невдалих входів: політика обмеження активувалася.
- `auth.token.invalid` для захищених маршрутів: прострочені чи змінені JWT, відсутня сесія.
- `auth.forbidden`: авторизований користувач пробує ресурс вищої ролі.
- `auth.mfa.fail`: невірний OTP, спроба обходу або проблема зі синхронізацією часу.

На production слід додати SIEM, alerting, обмеження доступу до логів, політику retention і контроль цілісності журналів. Локальний JSONL може бути змінений власником вузла та не є незаперечним доказом сам по собі.
