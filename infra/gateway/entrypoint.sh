#!/bin/sh
set -e
mkdir -p /certs
# 실인증서 주입 경로가 있으면 사용, 없으면 self-signed 자동 생성.
if [ -n "$TLS_CERT_PATH" ] && [ -f "$TLS_CERT_PATH" ]; then
  cp "$TLS_CERT_PATH" /certs/gateway.crt; cp "$TLS_KEY_PATH" /certs/gateway.key
  echo "[gateway] 주입된 TLS 인증서 사용"
elif [ ! -f /certs/gateway.crt ]; then
  echo "[gateway] self-signed 인증서 생성"
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout /certs/gateway.key -out /certs/gateway.crt \
    -subj "/CN=${GATEWAY_CN:-cyber-range.local}" >/dev/null 2>&1
fi
exec nginx -g 'daemon off;'
