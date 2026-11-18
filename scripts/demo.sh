#!/usr/bin/env bash
# Демонстрация ПР6 преподавателю. Запуск в Ubuntu (WSL) от root:
#   wsl -d Ubuntu -u root
#   cd "/mnt/c/Users/islam/Desktop/Клиент-серверные технологии и их безопасность/ПР6_CICD_SAST_SCA"
#   bash scripts/demo.sh <этап>
# Этапы: prepare | scan-v1 | scan-v2 | tls-before | tls-after | apps | attack | zap | stop
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
DEMO=/root/pr6-demo
C='\033[1;36m'; G='\033[1;32m'; N='\033[0m'
say()  { echo -e "\n${C}>>> $*${N}"; }
show() { echo -e "${C}\$ $*${N}"; eval "$@"; }
pause(){ [ -n "${DEMO_NOPAUSE:-}" ] && return; read -r -p "  [Enter — дальше] " _ </dev/tty || true; }

checkout() {   # копия репозитория на нужном теге (рабочую папку не трогаем)
  git config --global --add safe.directory '*' 2>/dev/null
  # только история до нужного тега/ветки — как в CI на этом коммите (Gitleaks проверяет всю историю клона)
  rm -rf "$DEMO-$1" && git clone -q --single-branch --branch "$1" "$REPO" "$DEMO-$1" 2>/dev/null
  cp "$REPO/scripts/run_scans.sh" "$DEMO-$1/scripts/run_scans.sh"
}

start_app() {  # start_app <порт> <каталог> <команда...>; PID сохраняется в /tmp/demo_<порт>.pid
  local port=$1 dir=$2; shift 2
  [ -f /tmp/demo_$port.pid ] && kill "$(cat /tmp/demo_$port.pid)" 2>/dev/null
  ( cd "$dir" && exec setsid nohup "$@" ) >/tmp/demo_$port.log 2>&1 < /dev/null &
  echo $! > /tmp/demo_$port.pid
}

wait_url() { for i in $(seq 1 60); do curl -s -o /dev/null "$1" && return 0; sleep 1; done; return 1; }

case "${1:-help}" in
prepare)   # один раз перед демонстрацией (~2–5 мин)
  say "Окружения Python, копии репозитория, образы Docker, сертификат"
  apt-get install -y -q python3-venv >/dev/null 2>&1 || true
  [ -x /opt/pr6tools/bin/bandit ] || { python3 -m venv /opt/pr6tools && /opt/pr6tools/bin/pip install -q "bandit[sarif]==1.8.6" pip-audit==2.9.0 pytest requests pyyaml; }
  checkout v1-vulnerable; checkout main
  [ -d /opt/pr6vuln ]  || python3 -m venv /opt/pr6vuln
  /opt/pr6vuln/bin/pip install -q pytest -r "$DEMO-v1-vulnerable/requirements.txt"
  [ -d /opt/pr6fixed ] || python3 -m venv /opt/pr6fixed
  /opt/pr6fixed/bin/pip install -q pytest -r "$DEMO-main/requirements.txt"
  for i in semgrep/semgrep aquasec/trivy zricethezav/gitleaks bkimminich/juice-shop zaproxy/zap-stable; do
    docker image inspect "$i" >/dev/null 2>&1 || docker pull -q "$i"; done
  [ -f /etc/nginx/ssl/server.crt ] || { mkdir -p /etc/nginx/ssl; openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt -subj "/C=KZ/ST=Astana/L=Astana/O=ENU/CN=localhost" 2>/dev/null; }
  echo -e "${G}Готово к демонстрации${N}" ;;

scan-v1|scan-v2)   # конвейер SAST/SCA локально (~1–2 мин)
  if [ "$1" = scan-v1 ]; then t=v1-vulnerable; py=/opt/pr6vuln/bin/python; else t=main; py=/opt/pr6fixed/bin/python; fi
  [ -d "$DEMO-$t" ] || checkout "$t"
  say "Конвейер безопасности на версии $t: Gitleaks, Semgrep, Bandit, pip-audit, Trivy, pytest"
  cd "$DEMO-$t" && git log --oneline -1
  APP_PY=$py bash scripts/run_scans.sh /tmp/demo-$t ;;

tls-before|tls-after)   # Nginx + OpenSSL + TLS gate
  [ "$1" = tls-before ] && conf=tls-weak.conf || conf=tls-hardened.conf
  [ -d "$DEMO-main" ] || checkout main
  SHOP_SECRET_KEY=$(openssl rand -hex 32) SHOP_DB=/tmp/shop_demo5000.db start_app 5000 "$DEMO-main" /opt/pr6fixed/bin/python -m src.shop.app
  say "Конфигурация nginx/$conf"
  cp "$REPO/nginx/$conf" /etc/nginx/sites-available/pr6-tls
  ln -sf /etc/nginx/sites-available/pr6-tls /etc/nginx/sites-enabled/pr6-tls
  show "nginx -t && systemctl reload nginx"
  wait_url http://127.0.0.1:5000/api/products; pause
  say "Подключение по TLS 1.2 и TLS 1.3"
  show "echo | openssl s_client -connect localhost:443 -tls1_2 2>/dev/null | grep -E '^New,|Server Temp Key|Peer signing'"
  show "echo | openssl s_client -connect localhost:443 -tls1_3 2>/dev/null | grep -E '^New,'"
  pause
  say "Попытка подключиться по устаревшему TLS 1.0"
  show "echo | openssl s_client -connect localhost:443 -tls1 -cipher 'ALL:@SECLEVEL=0' 2>&1 | grep -E '^New,|alert' | head -2"
  pause
  say "Заголовки ответа (HSTS, баннер сервера)"
  show "curl -sk -D - -o /dev/null https://localhost/api/products | grep -iE 'HTTP/|strict|server:'"
  pause
  say "TLS gate (тот же скрипт, что в CI)"
  bash "$REPO/scripts/tls_gate.sh" localhost 443 ;;

apps)   # v1 :5001, v2 :5002, Juice Shop :3000
  say "Запуск мишеней: v1 (5001), v2 (5002), OWASP Juice Shop (3000)"
  [ -d "$DEMO-v1-vulnerable" ] || checkout v1-vulnerable
  [ -d "$DEMO-main" ] || checkout main
  SHOP_DB=/tmp/shop_demo5001.db start_app 5001 "$DEMO-v1-vulnerable" /opt/pr6vuln/bin/python -c \
    "from src.shop import app as a, db; db.init_db(hasher=a.md5); a.app.run(host='0.0.0.0', port=5001)"
  SHOP_SECRET_KEY=$(openssl rand -hex 32) SHOP_DB=/tmp/shop_demo5002.db SHOP_PORT=5002 SHOP_HOST=0.0.0.0 \
    start_app 5002 "$DEMO-main" /opt/pr6fixed/bin/python -m src.shop.app
  docker ps --format '{{.Names}}' | grep -qx juice || docker run -d --name juice -p 3000:3000 bkimminich/juice-shop >/dev/null
  for u in http://localhost:5001/api/products http://localhost:5002/api/products http://localhost:3000/; do
    wait_url "$u"; printf "  %-38s HTTP %s\n" "$u" "$(curl -s -o /dev/null -w '%{http_code}' "$u")"; done ;;

attack)   # ручные атаки SQLi и IDOR на v1 и v2 (после этапа apps)
  J='-H Content-Type:application/json'
  for v in 5001 5002; do
    [ $v = 5001 ] && name="v1 (уязвимая)" || name="v2 (исправленная)"
    say "A03 SQL-инъекция во входе — $name"
    show "curl -s -w ' [HTTP %{http_code}]' -X POST localhost:$v/api/login $J -d '{\"username\":\"admin'\'' --\",\"password\":\"x\"}'"; echo; pause
    say "A03 UNION-инъекция в поиске — $name"
    show "curl -s \"localhost:$v/api/products?q=zzz'%20UNION%20SELECT%20id,username,password,role%20FROM%20users--\""; echo; pause
    say "A01 IDOR: aliya (id=2) запрашивает профиль Тимура (id=3) — $name"
    TOK=$(curl -s -X POST localhost:$v/api/login $J -d '{"username":"aliya","password":"Aliya#2026"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
    echo -e "${C}\$ curl -s localhost:$v/api/users/3 -H \"Authorization: Bearer ${TOK:0:24}...\"${N}"
    curl -s -w " [HTTP %{http_code}]" localhost:$v/api/users/3 -H "Authorization: Bearer $TOK"; echo; pause
  done
  say "A03 Juice Shop: обход входа ' OR 1=1--"
  show "curl -s -X POST localhost:3000/rest/user/login $J -d '{\"email\":\"'\'' OR 1=1--\",\"password\":\"x\"}' | cut -c1-200"; echo ;;

zap)   # графический ZAP в браузере: http://localhost:8080/zap/ (после этапа apps)
  say "OWASP ZAP GUI (Webswing). Откройте в браузере Windows: http://localhost:8080/zap/"
  docker rm -f zapgui >/dev/null 2>&1
  docker run -d --name zapgui --network host -u zap \
    -e ZAP_WEBSWING_OPTS="-host 0.0.0.0 -port 8090 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true" \
    zaproxy/zap-stable zap-webswing.sh >/dev/null
  wait_url http://localhost:8080/zap/
  echo "  Дождитесь окна ZAP, выберите «No, I do not want to persist» → Start, затем нажмите Enter здесь:"
  echo "  атаки пойдут через прокси ZAP (порт 8090), затем запустится активное сканирование v1."
  pause
  for i in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:8090/JSON/core/view/version/ && break; sleep 3; done
  curl -s -o /dev/null http://127.0.0.1:8090/JSON/core/view/version/ || {
    echo "  ZAP ещё не запущен: откройте http://localhost:8080/zap/ в браузере и повторите: bash scripts/demo.sh zap"; exit 1; }
  /opt/pr6tools/bin/python - <<'PY'
import requests, time
Z = "http://127.0.0.1:8090"; PX = {"http": Z}
def zap(p, **k): return requests.get(f"{Z}/JSON/{p}/", params=k, timeout=600).json()
s = lambda m, u, **k: requests.request(m, u, proxies=PX, timeout=30, **k)
s("POST", "http://localhost:3000/rest/user/login", json={"email": "' OR 1=1--", "password": "x"})
for b in ("http://localhost:5001", "http://localhost:5002"):
    s("POST", b + "/api/login", json={"username": "admin' --", "password": "x"})
    t = s("POST", b + "/api/login", json={"username": "aliya", "password": "Aliya#2026"}).json()["token"]
    s("GET", b + "/api/users/3", headers={"Authorization": "Bearer " + t})
    s("GET", b + "/api/products?q=usb")
print("  ручные запросы отправлены через ZAP — видны в Sites / History")
zap("ascan/action/setOptionMaxScanDurationInMins", Integer=3)
a = zap("ascan/action/scan", url="http://localhost:5001", recurse="true")["scan"]
while int(zap("ascan/view/status", scanId=a)["status"]) < 100:
    print("  active scan v1:", zap("ascan/view/status", scanId=a)["status"], "%"); time.sleep(10)
print("  готово, предупреждений:", zap("core/view/numberOfAlerts")["numberOfAlerts"], "— откройте вкладку Alerts")
PY
  ;;

stop)
  say "Остановка стенда"
  for f in /tmp/demo_*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; rm -f "$f"; done
  docker rm -f juice zapgui >/dev/null 2>&1
  rm -f /etc/nginx/sites-enabled/pr6-tls && systemctl reload nginx
  echo -e "${G}Стенд остановлен, сайт pr6-tls отключён${N}" ;;

*)
  echo "Этапы: prepare | scan-v1 | scan-v2 | tls-before | tls-after | apps | attack | zap | stop" ;;
esac
