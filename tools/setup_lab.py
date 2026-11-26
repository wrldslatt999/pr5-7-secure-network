"""Local-only initialization: generate secrets/certificates, create password-hashed accounts."""
import argparse
import getpass
import os
import pathlib
import secrets
import subprocess
import sys

ROOT=pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))

from server import storage
from server.models import password_ok
from server.logger_setup import log_event



def init():
    os.chdir(ROOT)
    target=ROOT/'.env'
    if not target.exists():
        text='SECURENET_JWT_SECRET='+secrets.token_urlsafe(48)+'\nSECURENET_DATA_DIR=runtime\nSECURENET_TOKEN_TTL=900\nSECURENET_LOGIN_LIMIT=5\nSECURENET_LOGIN_WINDOW=60\nSECURENET_ECHO_RPS=250\n'
        fd=os.open(str(target),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f:f.write(text)
        print('Generated local .env (do not commit)')
    else:
        print('Existing .env retained')
    certs=ROOT/'server'/'certs'
    if not (certs/'server.crt').exists() or not (certs/'ca.crt').exists():
        subprocess.run(['bash','server/scripts/gencerts.sh'],check=True,cwd=ROOT)
    else:
        print('Existing TLS material retained')
    storage.initialize()
    print('Initialized private runtime database')


def add_user(username,role):
    os.chdir(ROOT)
    storage.initialize()
    a=getpass.getpass(f'Password for {username} (hidden): ')
    b=getpass.getpass('Confirm password: ')
    if a!=b or not password_ok(a):
        raise ValueError('Passwords differ or are shorter than 12 UTF-8 bytes')
    storage.add_user(username,a,role)
    log_event('user.created',user=username)
    print('Created account:',username,'role:',role,'password stored as scrypt hash')


def main():
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('init')
    add=sub.add_parser('add-user');add.add_argument('--user',required=True);add.add_argument('--role',choices=['user','admin'],default='user')
    args=parser.parse_args()
    try:
        if args.command=='init':init()
        else:add_user(args.user,args.role)
    except (ValueError,subprocess.CalledProcessError) as exc:
        print('Error:',exc,file=sys.stderr);return 1
    return 0

if __name__=='__main__':sys.exit(main())
