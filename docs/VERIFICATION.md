# Протокол фактичної верифікації

**Дата підготовки:** 26.11.2026 (UTC+02:00).

## Що фактично виконано в середовищі підготовки проєкту (НЕ Kali користувача)

1. `python -m unittest discover -s tests -q` — **29 tests, OK** (реальні TCP/HTTPS listeners на loopback).
2. `python tools/security_scan.py` — **Checked 10 Python modules; findings=0**.
3. TLS certificate signed by generated local CA was validated; an untrusted second CA caused a `CERTIFICATE_VERIFY_FAILED` exception.
4. HTTP `/auth/login` was rejected with 426; HTTP echo and HTTPS echo were received with exact payload match.
5. HS256 JWT verification, wrong signature, expired token, `alg:none`, logout/revocation, user/admin ACL, MFA enrollment and OTP replay, brute force 429 verified in tests.
6. Benchmarks in `benchmarks/results.csv/json/md` are **measured locally**, not estimated. They include full connection setup, not only payload cipher cost.

**Not verified here:** deployment of two live Docker nodes, the exact IP assignment in Kali, the final GitHub Actions run. Those checks must be performed on the user's Kali / GitHub after uploading the project. Do not mark those as complete until there is actual evidence.

## Kali evidence checklist

- `docker compose ps` running two services.
- `docker compose exec server hostname -i` → compare to intended 172.28.57.10.
- `docker compose exec client hostname -i` → compare to intended 172.28.57.11.
- `docker compose exec client python -m client.client health` → HTTPS status 200 with valid CA.
- `client login --user alice` and `client whoami`; missing token 401, user admin 403.
- `client brute-demo` → 429.
- TOTP enrollment and a successful `login --otp` (do NOT show secret URI, password or JWT in screenshots).
- `python -m client.bench` from Kali, followed by `git add benchmarks/results.*`, commit and push.
- GitHub Actions shows successful tests for Python 3.11/3.12.

### Capturing test output without leaking credentials

```bash
python3 -m unittest discover -s tests -v 2>&1 | tee runtime/test-run.txt
python3 tools/security_scan.py | tee runtime/security-scan.txt
```

`runtime/` is ignored by Git. Put only evidence **without secrets** in a separate `docs/` file if required; never publish `ca.key`, `server.key`, `.env`, TOTP URI or a JWT.
