#!/usr/bin/env bash
set -euo pipefail
umask 077
mkdir -p server/certs
cd server/certs
if [[ -e ca.key || -e server.key ]]; then
  echo 'Existing private key material present; refusing to overwrite.' >&2
  exit 1
fi
# Local demonstration CA, separate CA + leaf certificates. Never commit ca.key.
openssl req -x509 -newkey rsa:3072 -sha256 -noenc -days 90 \
  -subj '/CN=SecureNetLab local CA' -keyout ca.key -out ca.crt \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -new -newkey rsa:3072 -sha256 -noenc \
  -subj '/CN=server' -keyout server.key -out server.csr >/dev/null 2>&1
cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1,IP:172.28.57.10
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 60 -sha256 -extfile server.ext >/dev/null 2>&1
openssl verify -CAfile ca.crt server.crt
rm -f server.csr server.ext ca.srl
chmod 600 ca.key server.key
chmod 644 ca.crt server.crt
printf 'CA trust anchor: server/certs/ca.crt\nLeaf cert: server/certs/server.crt\n'
