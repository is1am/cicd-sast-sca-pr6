#!/usr/bin/env bash
# Лабораторный прогон частей 1–2 и 3.1: Nginx + TLS «до» и «после» ужесточения.
# Запуск от root в Linux/WSL: scripts/tls_lab.sh <before|after> <каталог-результатов>
set -u
MODE=$1
OUT=$2
REPO=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUT"

# 1. Сертификат (один раз)
if [ ! -f /etc/nginx/ssl/server.crt ]; then
  mkdir -p /etc/nginx/ssl
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt \
    -subj "/C=KZ/ST=Astana/L=Astana/O=ENU/CN=localhost" 2>/dev/null
fi
openssl x509 -in /etc/nginx/ssl/server.crt -noout -subject -issuer -dates -fingerprint -sha256 >"$OUT/certificate.txt"

# 2. Конфигурация виртуального хоста
if [ "$MODE" = before ]; then CONF=tls-weak.conf; else CONF=tls-hardened.conf; fi
cp "$REPO/nginx/$CONF" /etc/nginx/sites-available/pr6-tls
ln -sf /etc/nginx/sites-available/pr6-tls /etc/nginx/sites-enabled/pr6-tls
{ echo "# nginx -t"; nginx -t 2>&1; } >"$OUT/nginx_test.txt"
systemctl reload nginx || systemctl restart nginx
sleep 1

# 3. OpenSSL s_client: TLS 1.2, TLS 1.3, TLS 1.0
echo | openssl s_client -connect localhost:443 -servername localhost -tls1_2 >"$OUT/openssl_tls12.txt" 2>&1
echo | openssl s_client -connect localhost:443 -servername localhost -tls1_3 >"$OUT/openssl_tls13.txt" 2>&1
echo | openssl s_client -connect localhost:443 -servername localhost -tls1 -cipher 'ALL:@SECLEVEL=0' >"$OUT/openssl_tls10.txt" 2>&1
echo | openssl s_client -connect localhost:443 -servername localhost -tls1_1 -cipher 'ALL:@SECLEVEL=0' >"$OUT/openssl_tls11.txt" 2>&1

# Перечень принятых шифров TLS 1.2 (перебор всех известных OpenSSL наборов)
: >"$OUT/ciphers_accepted.txt"
for c in $(openssl ciphers 'ALL:COMPLEMENTOFALL:@SECLEVEL=0' | tr ':' ' '); do
  for v in tls1 tls1_1 tls1_2; do
    if echo | timeout 3 openssl s_client -connect localhost:443 -$v -cipher "$c:@SECLEVEL=0" >/dev/null 2>&1; then
      echo "$v $c" >>"$OUT/ciphers_accepted.txt"
    fi
  done
done

# 4. Заголовки ответа
curl -sk -D - -o /dev/null https://localhost/api/products >"$OUT/headers.txt"

# 5. TLS gate
bash "$REPO/scripts/tls_gate.sh" localhost 443 >"$OUT/tls_gate.txt" 2>&1; echo "exit=$?" >>"$OUT/tls_gate.txt"

# 6. Захват рукопожатий: TLS 1.3, TLS 1.2 и попытка даунгрейда до TLS 1.0
tcpdump -i lo -U -w "$OUT/handshake.pcap" port 443 >/dev/null 2>&1 &
TP=$!; sleep 2
echo | openssl s_client -connect localhost:443 -servername localhost -tls1_3 >/dev/null 2>&1
echo | openssl s_client -connect localhost:443 -servername localhost -tls1_2 -cipher 'ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0' >/dev/null 2>&1
echo | openssl s_client -connect localhost:443 -servername localhost -tls1 -cipher 'ALL:@SECLEVEL=0' >/dev/null 2>&1
sleep 2; kill $TP; sleep 1
tshark -r "$OUT/handshake.pcap" -Y tls -o tls.desegment_ssl_records:TRUE \
  -T fields -E separator='|' -e frame.number -e tcp.stream -e tcp.srcport -e _ws.col.Info \
  -e tls.handshake.version -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite \
  -e tls.handshake.extensions_key_share_group -e tls.alert_message.desc 2>/dev/null >"$OUT/handshake_tshark.txt"
tshark -r "$OUT/handshake.pcap" -Y "tls.handshake.type==1 || tls.handshake.type==2 || tls.alert_message" -V 2>/dev/null \
  | grep -E "^Frame |Handshake Type|Version:|Cipher Suite:|Cipher Suites Length|Supported Version:|Group:|Alert Message|Level:|Description:" \
  >"$OUT/handshake_details.txt"

# 7. testssl.sh — глубокий аудит
docker run --rm --network host -v "$OUT:/out" drwetter/testssl.sh --quiet --color 0 --warnings off \
  --jsonfile /out/testssl.json --severity LOW https://localhost:443 >"$OUT/testssl.txt" 2>&1
docker run --rm --network host drwetter/testssl.sh --quiet --color 0 --warnings off \
  -p -s -f -P -U -h https://localhost:443 >"$OUT/testssl_full.txt" 2>&1
echo "done $MODE"
