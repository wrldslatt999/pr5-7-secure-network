"""Thread-safe, bounded, in-memory limits; see limitations about multi-worker use."""
import collections
import threading
import time


class RateLimiter:
    def __init__(self, login_limit=5, login_window=60, echo_rps=250):
        self.login_limit = int(login_limit)
        self.login_window = int(login_window)
        self.echo_rps = int(echo_rps)
        self._lock = threading.RLock()
        self._login = {}
        self._echo = {}

    def _take(self, store, key, limit, window):
        now = time.monotonic()
        with self._lock:
            if len(store) > 5000:  # drop stale; avoid unbounded cardinality
                for k, (start, _) in list(store.items()):
                    if now - start >= window:
                        store.pop(k, None)
            start, count = store.get(key, (now, 0))
            if now - start >= window:
                start, count = now, 0
            count += 1
            store[key] = (start, count)
            return count <= limit

    def allow_login(self, ip, username):
        # Per-account AND per-origin prevent trivial username/IP switching.
        a = self._take(self._login, ('account', username.casefold()), self.login_limit, self.login_window)
        b = self._take(self._login, ('source', ip), self.login_limit * 3, self.login_window)
        return a and b

    def allow_echo(self, ip):
        return self._take(self._echo, ip, self.echo_rps, 1)
