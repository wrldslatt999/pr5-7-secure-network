"""Executable security checks for authentication, access control, MFA, TLS, logs, and rate limiting."""
import json
import os
import pathlib
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.error

from server import security, storage
from server.app import create_server
from server.models import username_ok, password_ok, text_ok
from server.ratelimit import RateLimiter
from client.client import send_request
from tools.analyze_logs import collect
from tools.security_scan import scan

ROOT=pathlib.Path(__file__).resolve().parents[1]
PASSWORD='TestOnly-Strong-Phrase_2026!'


class AlgorithmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['SECURENET_JWT_SECRET']='TestOnly.' + secrets.token_urlsafe(48)
        os.environ['SECURENET_SCRYPT_N']='16384'  # only in test suite; production uses 32768

    def test_scrypt_password_verify(self):
        hashed=security.password_hash(PASSWORD)
        self.assertTrue(security.verify_password(PASSWORD,hashed))
        self.assertFalse(security.verify_password('bad',hashed))
        self.assertNotIn(PASSWORD,hashed)

    def test_invalid_hash_rejected(self):
        self.assertFalse(security.verify_password(PASSWORD,'not-a-scrypt-hash'))

    def test_random_salts(self):
        self.assertNotEqual(security.password_hash(PASSWORD),security.password_hash(PASSWORD))

    def test_jwt_roundtrip(self):
        token=security.make_token('alice')
        self.assertEqual(security.read_token(token)['sub'],'alice')

    def test_forged_jwt_signature_rejected(self):
        token=security.make_token('alice')
        bad=token[:-1] + ('A' if token[-1]!='A' else 'B')
        with self.assertRaises(ValueError):
            security.read_token(bad)

    def test_none_algorithm_rejected(self):
        token=security.make_token('alice')
        a,b,c=token.split('.')
        a=security._b64(b'{"alg":"none","typ":"JWT"}')
        with self.assertRaises(ValueError):
            security.read_token('.'.join((a,b,c)))

    def test_expired_jwt_rejected(self):
        token=security.make_token('alice',now=int(time.time())-200,ttl=10)
        with self.assertRaises(ValueError):
            security.read_token(token)

    def test_future_token_rejected(self):
        token=security.make_token('alice',now=int(time.time())+120)
        with self.assertRaises(ValueError):
            security.read_token(token)

    def test_totp_same_step_and_bad(self):
        secret=security.new_totp_secret()
        step=int(time.time()//30)
        code=security._totp_code(secret,step)
        self.assertEqual(security.totp_match_step(secret,code),step)
        self.assertIsNone(security.totp_match_step(secret,'nototp'))
        self.assertIsNone(security.totp_match_step(secret,code,last_step=step))

    def test_input_validation(self):
        self.assertTrue(username_ok('alice'))
        self.assertFalse(username_ok('../secrets'))
        self.assertFalse(password_ok('short'))
        self.assertFalse(text_ok('x'*5000))

    def test_rate_limit_independence(self):
        limiter=RateLimiter(login_limit=2,login_window=60,echo_rps=3)
        self.assertTrue(limiter.allow_login('127.0.0.1','foo'))
        self.assertTrue(limiter.allow_login('127.0.0.1','foo'))
        self.assertFalse(limiter.allow_login('127.0.0.1','foo'))
        self.assertTrue(limiter.allow_login('127.0.0.1','bar'))

    def test_static_scanner_clean(self):
        for d in ['server','client']:
            for path in (ROOT/d).glob('*.py'):
                self.assertEqual(scan(path),[],str(path))


class RealTLSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous_env=os.environ.copy()
        cls.temp=tempfile.TemporaryDirectory(prefix='securenet-integration-')
        os.environ['SECURENET_DATA_DIR']=cls.temp.name
        os.environ['SECURENET_JWT_SECRET']=secrets.token_urlsafe(48)
        os.environ['SECURENET_SCRYPT_N']='16384'
        os.environ['SECURENET_LOGIN_LIMIT']='5'
        os.environ['SECURENET_LOGIN_WINDOW']='60'
        storage.initialize()
        storage.add_user('alice',PASSWORD,'user')
        storage.add_user('admin',PASSWORD,'admin')
        storage.add_user('mfauser',PASSWORD,'user')
        if not (ROOT/'server/certs/server.crt').is_file():
            subprocess.run(['bash','server/scripts/gencerts.sh'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
        cls.ca=str(ROOT/'server/certs/ca.crt')
        cls.http=create_server('127.0.0.1',0,tls=False)
        cls.https=create_server('127.0.0.1',0,tls=True,certificate=str(ROOT/'server/certs/server.crt'),keyfile=str(ROOT/'server/certs/server.key'))
        cls.http_url=f'http://127.0.0.1:{cls.http.server_address[1]}'
        cls.https_url=f'https://127.0.0.1:{cls.https.server_address[1]}'
        cls.threads=[]
        for instance in (cls.http,cls.https):
            thread=threading.Thread(target=instance.serve_forever,daemon=True)
            thread.start();cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for s in (cls.http,cls.https):s.shutdown();s.server_close()
        cls.temp.cleanup()
        os.environ.clear();os.environ.update(cls.previous_env)

    def setUp(self):
        self.https.limiter=RateLimiter(login_limit=5,echo_rps=60)
        self.http.limiter=RateLimiter(login_limit=5,echo_rps=60)

    def request(self,path,body=None,token=None,tls=True):
        return send_request(self.https_url if tls else self.http_url,path,body,token,ca=self.ca)

    def login(self,user='alice',otp=None):
        body={'username':user,'password':PASSWORD}
        if otp:body['otp']=otp
        return self.request('/auth/login',body)

    def test_http_echo_roundtrip(self):
        self.assertEqual(self.request('/echo-http',{'msg':'hello'},tls=False),(200,{'echo':'hello'}))

    def test_tls_echo_roundtrip(self):
        self.assertEqual(self.request('/echo-http',{'msg':'київ'},tls=True),(200,{'echo':'київ'}))

    def test_tls_certificate_validation(self):
        wrong_ca=pathlib.Path(self.temp.name)/'other-ca.crt'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-noenc','-days','1',
                        '-subj','/CN=Untrusted Test Authority',
                        '-keyout',str(pathlib.Path(self.temp.name)/'other-ca.key'),'-out',str(wrong_ca)],
                        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with self.assertRaises(urllib.error.URLError) as error:
            send_request(self.https_url,'/health',ca=str(wrong_ca))
        self.assertIsInstance(error.exception.reason, ssl.SSLCertVerificationError)

    def test_http_credentials_forbidden(self):
        with self.assertRaises(ValueError):
            send_request(self.http_url,'/auth/login',{'username':'alice','password':PASSWORD})

    def test_server_refuses_plaintext_auth(self):
        import urllib.request,urllib.error
        req=urllib.request.Request(self.http_url+'/auth/login',data=json.dumps({'username':'alice','password':PASSWORD}).encode(),headers={'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(req,timeout=5)
        self.assertEqual(err.exception.code,426)

    def test_login_and_protected_echo(self):
        status,body=self.login()
        self.assertEqual(status,200)
        self.assertEqual(self.request('/whoami',token=body['access_token'])[0],200)
        status,payload=self.request('/echo-secure',{'msg':'private'},token=body['access_token'])
        self.assertEqual((status,payload['echo']),(200,'private'))

    def test_missing_token_401(self):
        self.assertEqual(self.request('/whoami')[0],401)

    def test_wrong_password_401(self):
        self.assertEqual(self.request('/auth/login',{'username':'alice','password':'Wrong-but-well-formed-password'})[0],401)

    def test_user_cannot_read_admin(self):
        _,body=self.login('alice')
        self.assertEqual(self.request('/admin/overview',token=body['access_token'])[0],403)

    def test_admin_role(self):
        _,body=self.login('admin')
        self.assertEqual(self.request('/admin/overview',token=body['access_token'])[0],200)

    def test_bad_token_rejected(self):
        self.assertEqual(self.request('/whoami',token='a.b.c')[0],401)

    def test_expired_token_rejected(self):
        token=security.make_token('alice',now=int(time.time())-100,ttl=1)
        self.assertEqual(self.request('/whoami',token=token)[0],401)

    def test_logout_revokes_token(self):
        _,body=self.login('alice');token=body['access_token']
        self.assertEqual(self.request('/auth/logout',body={},token=token)[0],200)
        self.assertEqual(self.request('/whoami',token=token)[0],401)

    def test_rate_limit_brute_attempts(self):
        statuses=[self.request('/auth/login',{'username':'unknown','password':'Wrong-but-well-formed-password'})[0] for _ in range(7)]
        self.assertEqual(statuses[:5],[401]*5)
        self.assertEqual(statuses[5:], [429,429])

    def test_mfa_enrollment_login_replay(self):
        status,token_info=self.login('mfauser')
        self.assertEqual(status,200)
        token=token_info['access_token']
        status,body=self.request('/auth/mfa/setup',{'password':PASSWORD},token=token)
        self.assertEqual(status,200)
        secret=urllib.parse.parse_qs(urllib.parse.urlsplit(body['otpauth_uri']).query)['secret'][0]
        step=int(time.time()//30)
        code=security._totp_code(secret,step)
        self.assertEqual(self.request('/auth/mfa/confirm',{'otp':code},token=token)[0],200)
        # Previously issued token lacks MFA claim and loses access after enabling MFA.
        self.assertEqual(self.request('/whoami',token=token)[0],401)
        self.assertEqual(self.login('mfauser')[0],401)
        next_code=security._totp_code(secret,step+1)
        self.assertEqual(self.login('mfauser',otp=next_code)[0],200)
        self.assertEqual(self.login('mfauser',otp=next_code)[0],401)

    def test_json_size_limit(self):
        self.assertEqual(self.request('/echo-http',{'msg':'x'*5000})[0],400)

    def test_log_analysis_filters(self):
        self.login('admin')
        events=collect(pathlib.Path(self.temp.name)/'events.jsonl',user='admin',event='auth.ok')
        self.assertTrue(events)
        text=(pathlib.Path(self.temp.name)/'events.jsonl').read_text(encoding='utf-8')
        self.assertNotIn(PASSWORD,text)
        self.assertNotIn('access_token',text)


if __name__=='__main__':unittest.main()
