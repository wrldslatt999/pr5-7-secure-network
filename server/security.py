"""Scrypt password storage, strict HS256 JWT and RFC 6238 TOTP implemented with stdlib."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
import urllib.parse

ISSUER = 'secure-net-lab'
AUDIENCE = 'secure-net-client'


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _unb64(value):
    if not isinstance(value, str) or len(value) > 8192 or not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in value):
        raise ValueError('Invalid encoding')
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def password_hash(plain):
    # OWASP prefers Argon2id; scrypt is used here because stdlib-only / offline.
    n = int(os.environ.get('SECURENET_SCRYPT_N', '131072'))
    if n < 16384 or n > 131072 or n & (n - 1):
        raise ValueError('Invalid scrypt cost')
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(plain.encode('utf-8'), salt=salt, n=n, r=8, p=1, dklen=32, maxmem=256*1024*1024)
    return f'scrypt${n}$8$1${_b64(salt)}${_b64(derived)}'


def verify_password(plain, encoded):
    try:
        alg, ns, rs, ps, salt, expected = encoded.split('$')
        n, r, p = int(ns), int(rs), int(ps)
        if alg != 'scrypt' or not (16384 <= n <= 131072) or r != 8 or p != 1:
            return False
        found = hashlib.scrypt(plain.encode('utf-8'), salt=_unb64(salt), n=n, r=r, p=p, dklen=32, maxmem=256*1024*1024)
        return hmac.compare_digest(found, _unb64(expected))
    except (ValueError, TypeError, MemoryError):
        return False


def jwt_secret():
    val = os.getenv('SECURENET_JWT_SECRET', '')
    if len(val.encode('utf-8')) < 32 or val == 'GENERATE_VIA_SETUP_SCRIPT':
        raise RuntimeError('SECURENET_JWT_SECRET must contain >=32 bytes of random material')
    return val.encode('utf-8')


def make_token(subject, mfa=False, now=None, ttl=None):
    now = int(time.time()) if now is None else int(now)
    ttl = int(os.getenv('SECURENET_TOKEN_TTL', '900')) if ttl is None else int(ttl)
    claims = {'sub': subject, 'iss': ISSUER, 'aud': AUDIENCE, 'iat': now, 'nbf': now,
              'exp': now + ttl, 'jti': secrets.token_hex(16), 'mfa': bool(mfa)}
    header = {'alg': 'HS256', 'typ': 'JWT'}
    parts = [_b64(json.dumps(x, separators=(',', ':'), sort_keys=True).encode()) for x in (header, claims)]
    msg = '.'.join(parts)
    signature = hmac.new(jwt_secret(), msg.encode('ascii'), hashlib.sha256).digest()
    return msg + '.' + _b64(signature)


def read_token(token, now=None):
    if not isinstance(token, str) or len(token) > 4096 or token.count('.') != 2:
        raise ValueError('Malformed token')
    first, second, signature = token.split('.')
    try:
        header = json.loads(_unb64(first))
        claims = json.loads(_unb64(second))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Malformed token') from exc
    if header != {'alg': 'HS256', 'typ': 'JWT'}:
        raise ValueError('Unsupported signing algorithm')
    expected = hmac.new(jwt_secret(), (first + '.' + second).encode('ascii'), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _unb64(signature)):
        raise ValueError('Signature failed')
    t = int(time.time()) if now is None else int(now)
    if (claims.get('iss') != ISSUER or claims.get('aud') != AUDIENCE or
        type(claims.get('exp')) is not int or claims['exp'] <= t or
        type(claims.get('nbf')) is not int or claims['nbf'] > t or
        type(claims.get('iat')) is not int or claims['iat'] > t or
        not isinstance(claims.get('sub'), str) or
        not isinstance(claims.get('jti'), str) or len(claims['jti']) != 32 or
        type(claims.get('mfa')) is not bool):
        raise ValueError('Expired or invalid token')
    return claims


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def _totp_code(secret, counter):
    raw = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
    digest = hmac.new(raw, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0xf
    return f'{(struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}'


def totp_match_step(secret, code, now=None, last_step=-1):
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    step = int((time.time() if now is None else now) // 30)
    for delta in (-1, 0, 1):
        candidate = step + delta
        if candidate > last_step and hmac.compare_digest(_totp_code(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(user, secret):
    return 'otpauth://totp/' + urllib.parse.quote('SecureNetLab:'+user, safe='') + '?' + urllib.parse.urlencode({'secret': secret, 'issuer': 'SecureNetLab', 'algorithm': 'SHA1', 'digits': 6, 'period': 30})
