"""Input validation for the teaching API; never log secrets or JSON bodies."""
import re

USER_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{2,31}$")


def username_ok(value):
    return isinstance(value, str) and bool(USER_RE.fullmatch(value))


def password_ok(value):
    return isinstance(value, str) and 12 <= len(value.encode("utf-8")) <= 256


def text_ok(value):
    return isinstance(value, str) and len(value.encode("utf-8")) <= 4096
