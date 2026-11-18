#!/usr/bin/env bash
# TLS gate для CI: проверяет, что сервер отклоняет устаревшие протоколы и слабые шифры
# и отдаёт HSTS. Код возврата 1 — конфигурация не прошла проверку.
# Использование: tls_gate.sh <host> <port>
HOST=${1:-localhost}
PORT=${2:-443}
FAIL=0

try() {   # try <описание> <ожидание: accept|reject> <аргументы openssl s_client>
  local name=$1 expect=$2; shift 2
  echo | timeout 5 openssl s_client -connect "$HOST:$PORT" -servername "$HOST" "$@" >/tmp/tls_out 2>&1
  # строка «New, TLSv1.x, Cipher is <набор>» печатается для TLS 1.0–1.3; при отказе — «Cipher is (NONE)»
  if grep -qE "^New, .*Cipher is [A-Z0-9_-]+$" /tmp/tls_out; then
    got=accept
    proto=$(grep -m1 -E "^ *Protocol *:" /tmp/tls_out | awk '{print $3}')
    [ -z "$proto" ] && proto=$(grep -m1 -E "^New, " /tmp/tls_out | cut -d, -f2 | tr -d ' ')
    detail="$proto $(grep -m1 -E "^New, " /tmp/tls_out | sed 's/.*Cipher is //')"
  else
    got=reject; detail=$(grep -m1 -iE "alert|error|no protocols|handshake" /tmp/tls_out | cut -c1-90)
  fi
  if [ "$got" = "$expect" ]; then st=PASS; else st=FAIL; FAIL=1; fi
  printf "%-4s %-34s ожидается %-6s получено %-6s %s\n" "$st" "$name" "$expect" "$got" "$detail"
}

# Для проверки старых протоколов клиенту нужен SECLEVEL=0, иначе OpenSSL 3 откажет сам.
try "TLS 1.0"                       reject -tls1   -cipher 'ALL:@SECLEVEL=0'
try "TLS 1.1"                       reject -tls1_1 -cipher 'ALL:@SECLEVEL=0'
try "TLS 1.2"                       accept -tls1_2
try "TLS 1.3"                       accept -tls1_3
try "Шифры без PFS (RSA kx)"        reject -tls1_2 -cipher 'AES128-SHA:AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384'
try "CBC-шифры (SHA1)"              reject -tls1_2 -cipher 'ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:@SECLEVEL=0'
try "3DES / RC4 / NULL / EXPORT"    reject -tls1_2 -cipher '3DES:RC4:NULL:EXPORT:@SECLEVEL=0'

hsts=$(curl -sk -o /dev/null -D - "https://$HOST:$PORT/" | grep -i '^strict-transport-security' | tr -d '\r')
if echo "$hsts" | grep -qiE 'max-age=([0-9]{8,}|3[0-9]{7})'; then
  echo "PASS HSTS                               $hsts"
else
  echo "FAIL HSTS                               заголовок отсутствует или max-age < 1 года"; FAIL=1
fi

[ $FAIL -eq 0 ] && echo "TLS gate: OK" || echo "TLS gate: FAILED"
exit $FAIL
