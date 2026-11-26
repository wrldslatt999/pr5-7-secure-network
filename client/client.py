"""Verified TLS client for the SecureNetLab teaching service; no verify=False."""
import argparse
import getpass
import json
import os
import pathlib
import ssl
import sys
import urllib.error
import urllib.request

DEFAULT_HTTP = os.getenv('SECURENET_HTTP_URL', 'http://127.0.0.1:8080')
DEFAULT_HTTPS = os.getenv('SECURENET_HTTPS_URL', 'https://127.0.0.1:8443')
DEFAULT_CA = os.getenv('SECURENET_CA_FILE', 'server/certs/ca.crt')
TOKEN_FILE = pathlib.Path(os.getenv('SECURENET_TOKEN_FILE', 'runtime/client_session.json'))


def send_request(base, path, body=None, token=None, ca=None, timeout=10):
    if not base.startswith(('https://', 'http://')):
        raise ValueError('Unsupported protocol')
    if base.startswith('http://') and (token is not None or path not in ('/echo-http','/health')):
        raise ValueError('Credentials and tokens cannot be sent via plaintext HTTP')
    raw = None if body is None else json.dumps(body).encode('utf-8')
    headers = {'Accept':'application/json'}
    if raw is not None:
        headers['Content-Type']='application/json'
    if token:
        headers['Authorization']='Bearer '+token
    req = urllib.request.Request(base.rstrip('/')+path, data=raw, headers=headers,
                                 method='POST' if raw is not None else 'GET')
    context = ssl.create_default_context(cafile=ca or DEFAULT_CA) if base.startswith('https://') else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as err:
        try:
            detail = json.loads(err.read())
        except (json.JSONDecodeError, UnicodeError):
            detail = {'detail':'HTTP error'}
        return err.code, detail


def load_token():
    if not TOKEN_FILE.is_file():
        raise ValueError('Log in first (client login)')
    return json.loads(TOKEN_FILE.read_text(encoding='utf-8'))['token']


def save_token(token):
    TOKEN_FILE.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(str(TOKEN_FILE),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as f:
        json.dump({'token':token},f)


def main():
    p=argparse.ArgumentParser(description='SecureNetLab client: TLS certificates always verified')
    p.add_argument('--http-url',default=DEFAULT_HTTP)
    p.add_argument('--https-url',default=DEFAULT_HTTPS)
    p.add_argument('--ca',default=DEFAULT_CA,help='CA PEM for HTTPS hostname verification')
    subs=p.add_subparsers(dest='command',required=True)
    echo=subs.add_parser('echo');echo.add_argument('--http',action='store_true');echo.add_argument('--msg',default='Hello secure network')
    subs.add_parser('health')
    login=subs.add_parser('login');login.add_argument('--user',required=True);login.add_argument('--otp',action='store_true',help='Prompt for time-based OTP')
    subs.add_parser('whoami');subs.add_parser('admin');subs.add_parser('logout')
    setup=subs.add_parser('mfa-setup');setup.add_argument('--user',required=True)
    subs.add_parser('mfa-confirm')
    brute=subs.add_parser('brute-demo');brute.add_argument('--user',default='alice');brute.add_argument('--attempts',type=int,default=7)
    args=p.parse_args()
    http,https,ca=args.http_url,args.https_url,args.ca
    status=0;result={}
    try:
        if args.command=='echo':
            token=None if args.http else load_token()
            status,result=send_request(http if args.http else https,
                                      '/echo-http' if args.http else '/echo-secure',
                                      {'msg':args.msg},token,ca)
        elif args.command=='health':
            status,result=send_request(https,'/health',ca=ca)
        elif args.command=='login':
            password=getpass.getpass('Password (hidden): ')
            otp=getpass.getpass('TOTP (hidden): ') if args.otp else None
            payload={'username':args.user,'password':password}
            if otp is not None:
                payload['otp']=otp
            status,result=send_request(https,'/auth/login',payload,ca=ca)
            if status==200:
                save_token(result['access_token'])
                result={'status':'authenticated','expires_in':result['expires_in'],'token_file':str(TOKEN_FILE)}
        elif args.command in ('whoami','admin','logout'):
            path={'whoami':'/whoami','admin':'/admin/overview','logout':'/auth/logout'}[args.command]
            status,result=send_request(https,path,{} if args.command=='logout' else None,load_token(),ca)
            if args.command=='logout' and status==200:
                TOKEN_FILE.unlink(missing_ok=True)
        elif args.command=='mfa-setup':
            passwd=getpass.getpass('Repeat account password (hidden): ')
            status,result=send_request(https,'/auth/mfa/setup',{'password':passwd},load_token(),ca)
            if status==200:
                print('CONFIDENTIAL: Enroll this otpauth:// URI in an authenticator; do not publish/screenshare it.')
        elif args.command=='mfa-confirm':
            otp=getpass.getpass('Current TOTP from authenticator: ')
            status,result=send_request(https,'/auth/mfa/confirm',{'otp':otp},load_token(),ca)
            if status==200:
                TOKEN_FILE.unlink(missing_ok=True)
        elif args.command=='brute-demo':
            if not 1 <= args.attempts <= 15:
                raise ValueError('brute-demo limited to 1..15 attempts')
            for i in range(args.attempts):
                status,result=send_request(https,'/auth/login',
                                          {'username':args.user,'password':'NotAValidDemoPassword123!'},ca=ca)
                print(f'attempt {i+1}: HTTP {status}')
                if status==429:break
            return 0 if status==429 else 1
    except (OSError, ValueError, ssl.SSLError, urllib.error.URLError) as exc:
        print('Client error:',str(exc),file=sys.stderr)
        return 2
    print('HTTP',status)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if status==200 else 1

if __name__=='__main__':
    sys.exit(main())
