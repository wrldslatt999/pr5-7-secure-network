"""Client/server JSON API: intentionally plaintext demo and authenticated HTTPS."""
import argparse
import http.server
import json
import os
import secrets
import ssl
import threading
import time
import urllib.parse

from server.logger_setup import log_event
from server.models import username_ok, password_ok, text_ok
from server.ratelimit import RateLimiter
from server import security, storage

MAX_BODY = 8192
# Constant-cost check for nonexistent usernames to reduce timing-based enumeration.
DUMMY_HASH = security.password_hash(secrets.token_urlsafe(24))
PASSWORD_WORKERS = threading.BoundedSemaphore(2)


class APIHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'SecureNetLab'
    sys_version = ''

    def log_message(self, format, *args):  # no terminal logs containing user-controlled strings
        pass

    def _respond(self, code, payload):
        encoded = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Connection','close')
        self.end_headers()
        self.wfile.write(encoded)
        self.close_connection = True
        return code

    def _json_body(self):
        try:
            length = int(self.headers.get('Content-Length','0'))
        except ValueError:
            raise ValueError('Invalid request length')
        if not 0 < length <= MAX_BODY:
            raise ValueError('Request too large or empty')
        raw = self.rfile.read(length)
        obj = json.loads(raw.decode('utf-8'))
        if not isinstance(obj, dict):
            raise ValueError('JSON object required')
        return obj

    def _require_tls(self):
        return isinstance(self.connection, ssl.SSLSocket)

    def _principal(self):
        auth = self.headers.get('Authorization','')
        if len(auth) > 4200 or not auth.startswith('Bearer '):
            raise PermissionError('Missing bearer token')
        try:
            claims = security.read_token(auth[7:])
        except (ValueError, TypeError, AttributeError, UnicodeError) as exc:
            raise PermissionError('Invalid bearer token') from exc
        if storage.is_revoked(claims['jti']):
            raise PermissionError('Revoked token')
        user = storage.get_user(claims['sub'])
        if user is None:
            raise PermissionError('Unknown account')
        if user['totp_secret'] and not claims['mfa']:
            raise PermissionError('MFA required for this session')
        self._user = user['username']
        return user, claims

    def do_GET(self):
        self._process('GET')

    def do_POST(self):
        self._process('POST')

    def _process(self, method):
        started = time.perf_counter()
        path = urllib.parse.urlsplit(self.path).path
        self._user = None
        status = 500
        try:
            if path not in {'/health','/echo-http','/auth/login','/auth/mfa/setup','/auth/mfa/confirm','/auth/logout','/whoami','/admin/overview','/echo-secure'}:
                status=self._respond(404, {'detail':'Not found'})
            elif not self._require_tls() and path not in {'/health','/echo-http'}:
                status=self._respond(426, {'detail':'HTTPS required'})
            elif method=='GET' and path=='/health':
                status=self._respond(200, {'status':'ok','transport':'https' if self._require_tls() else 'http'})
            elif method=='POST' and path=='/echo-http':
                data=self._json_body()
                if not text_ok(data.get('msg')):
                    status=self._respond(400, {'detail':'Invalid text'})
                elif not self.server.limiter.allow_echo(self.client_address[0]):
                    log_event('rate.limit',ip=self.client_address[0],path=path)
                    status=self._respond(429, {'detail':'Rate limit exceeded'})
                else:
                    status=self._respond(200, {'echo':data['msg']})
            elif method=='POST' and path=='/auth/login':
                status=self._login()
            elif method=='POST' and path=='/auth/mfa/setup':
                status=self._mfa_setup()
            elif method=='POST' and path=='/auth/mfa/confirm':
                status=self._mfa_confirm()
            elif method=='POST' and path=='/auth/logout':
                _,claims=self._principal();storage.revoke_token(claims['jti'],claims['exp'])
                log_event('auth.logout', user=self._user,ip=self.client_address[0])
                status=self._respond(200, {'status':'logged-out'})
            elif method=='GET' and path=='/whoami':
                user, claims=self._principal()
                status=self._respond(200,{'username':user['username'],'role':user['role'],'mfa':claims['mfa'],'expires_at':claims['exp']})
            elif method=='GET' and path=='/admin/overview':
                user,_=self._principal()
                if user['role']!='admin':
                    log_event('auth.forbidden',user=self._user,ip=self.client_address[0],path=path)
                    status=self._respond(403, {'detail':'Insufficient privileges'})
                else:
                    status=self._respond(200, {'restricted':'admin','status':'ok'})
            elif method=='POST' and path=='/echo-secure':
                user,_=self._principal()
                data=self._json_body()
                status=self._respond(200,{'echo':data['msg'],'username':user['username']}) if text_ok(data.get('msg')) else self._respond(400,{'detail':'Invalid text'})
            else:
                status=self._respond(405,{'detail':'Method not allowed'})
        except (PermissionError, ValueError) as exc:
            if isinstance(exc, PermissionError):
                log_event('auth.token.invalid',ip=self.client_address[0],path=path)
                status=self._respond(401,{'detail':'Invalid or expired authorization'})
            else:
                status=self._respond(400,{'detail':'Malformed request'})
        except (ConnectionResetError, BrokenPipeError, TimeoutError):
            status=499
        except (UnicodeError, json.JSONDecodeError):
            status=self._respond(400,{'detail':'Malformed JSON'})
        except Exception:
            # Never include internal exceptions in responses; unexpected errors logged only as metadata.
            status=self._respond(500,{'detail':'Internal server error'})
        finally:
            log_event('http.request',user=self._user,ip=self.client_address[0],path=path,status=status,elapsed_ms=(time.perf_counter()-started)*1000)

    def _login(self):
        data=self._json_body()
        username=data.get('username')
        passwd=data.get('password')
        ip=self.client_address[0]
        if not username_ok(username) or not password_ok(passwd):
            return self._respond(400,{'detail':'Invalid input format'})
        if not self.server.limiter.allow_login(ip,username):
            log_event('rate.limit',user=username,ip=ip,path='/auth/login')
            return self._respond(429,{'detail':'Too many attempts; retry later'})
        user=storage.get_user(username)
        with PASSWORD_WORKERS:
            password_matches=security.verify_password(passwd, user['pwd_hash'] if user else DUMMY_HASH)
        if user is None or not password_matches:
            log_event('auth.fail',user=username,ip=ip)
            return self._respond(401,{'detail':'Invalid credentials'})
        if user['totp_secret']:
            step=security.totp_match_step(user['totp_secret'],data.get('otp'),last_step=user['last_totp_step'])
            if step is None or not storage.consume_totp(username,step):
                log_event('auth.mfa.fail',user=username,ip=ip)
                return self._respond(401,{'detail':'Invalid credentials'})
        token=security.make_token(username,mfa=bool(user['totp_secret']))
        log_event('auth.ok',user=username,ip=ip)
        return self._respond(200,{'access_token':token,'token_type':'bearer','expires_in':int(os.getenv('SECURENET_TOKEN_TTL','900'))})

    def _mfa_setup(self):
        user,_=self._principal()
        data=self._json_body()
        password=data.get('password')
        if user['totp_secret'] or not password_ok(password):
            return self._respond(403,{'detail':'MFA setup unavailable'})
        with PASSWORD_WORKERS:
            verified=security.verify_password(password,user['pwd_hash'])
        if not verified:
            return self._respond(403,{'detail':'MFA setup unavailable'})
        secret=security.new_totp_secret()
        storage.set_pending_totp(user['username'],secret)
        log_event('auth.mfa.setup',user=user['username'],ip=self.client_address[0])
        return self._respond(200,{'otpauth_uri':security.provisioning_uri(user['username'],secret),'note':'Keep this URI confidential; confirm within 10 minutes'})

    def _mfa_confirm(self):
        user,_=self._principal()
        data=self._json_body()
        now=int(time.time())
        if user['totp_secret'] or not user['pending_totp_secret'] or not user['pending_since'] or now-user['pending_since']>600:
            return self._respond(403,{'detail':'No valid pending MFA setup'})
        step=security.totp_match_step(user['pending_totp_secret'],data.get('otp'),now=now)
        if step is None or not storage.confirm_totp(user['username'],user['pending_totp_secret'],step):
            log_event('auth.mfa.fail',user=user['username'],ip=self.client_address[0])
            return self._respond(401,{'detail':'Invalid one-time code'})
        log_event('auth.mfa.enabled',user=user['username'],ip=self.client_address[0])
        return self._respond(200,{'status':'MFA enabled; log in again using OTP'})


class SecureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self,address,handler=APIHandler,login_limit=None,echo_rps=None):
        super().__init__(address,handler)
        self.limiter=RateLimiter(login_limit or int(os.getenv('SECURENET_LOGIN_LIMIT','5')),
                                int(os.getenv('SECURENET_LOGIN_WINDOW','60')),
                                echo_rps or int(os.getenv('SECURENET_ECHO_RPS','250')))

    def get_request(self):
        sock,addr=super().get_request()
        sock.settimeout(10)
        return sock,addr


def create_server(host,port,tls=False,certificate=None,keyfile=None,login_limit=None,echo_rps=None):
    storage.initialize()
    if tls:
        security.jwt_secret()  # fail closed when JWT signing secret is absent
    server=SecureServer((host,port),login_limit=login_limit,echo_rps=echo_rps)
    if tls:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=certificate or 'server/certs/server.crt',keyfile=keyfile or 'server/certs/server.key')
        # Handshake happens before BaseHTTPRequestHandler; TLS failure logged by underlying ssl.
        server.socket=ctx.wrap_socket(server.socket,server_side=True)
    return server


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=8443)
    parser.add_argument('--tls',action='store_true')
    parser.add_argument('--cert',default='server/certs/server.crt')
    parser.add_argument('--key',default='server/certs/server.key')
    args=parser.parse_args()
    server=create_server(args.host,args.port,tls=args.tls,certificate=args.cert,keyfile=args.key)
    print(f'Listening on {"HTTPS" if args.tls else "HTTP"} {args.host}:{args.port}',flush=True)
    try:
        server.serve_forever(poll_interval=.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__=='__main__':
    main()
