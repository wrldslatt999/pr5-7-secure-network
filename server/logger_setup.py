"""Structured JSONL security event logging. Does not retain passwords, tokens or OTP."""
import datetime
import json
import os
import pathlib
import threading

_lock = threading.Lock()
_SAFE_EVENTS = frozenset({
    'http.request','auth.ok','auth.fail','auth.mfa.fail','auth.mfa.setup',
    'auth.mfa.enabled','auth.logout','auth.token.invalid','auth.forbidden',
    'rate.limit','user.created','tls.handshake.fail',
})


def log_event(name, *, user=None, ip=None, status=None, path=None, elapsed_ms=None):
    if name not in _SAFE_EVENTS:
        raise ValueError("unrecognized event")
    root = pathlib.Path(os.getenv('SECURENET_DATA_DIR', 'runtime'))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    file = root / 'events.jsonl'
    # Only controlled metadata; no request body, password, secret, session or full token.
    event = {'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'event': name}
    if isinstance(user, str):
        event['user'] = user[:32]
    if isinstance(ip, str):
        event['ip'] = ip[:45]
    if isinstance(status, int):
        event['status'] = status
    if isinstance(path, str):
        event['path'] = path[:60]
    if isinstance(elapsed_ms, (int, float)):
        event['elapsed_ms'] = round(elapsed_ms, 3)
    with _lock:
        fd = os.open(str(file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'a', encoding='utf-8') as out:
            out.write(json.dumps(event, ensure_ascii=False, separators=(',', ':')) + '\n')
