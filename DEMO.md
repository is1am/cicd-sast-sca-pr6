# Демонстрация ПР6 преподавателю (≈15 минут)

## Перед парой (один раз, ~5 минут)

1. Открыть **Терминал Windows** → вкладка Ubuntu, или PowerShell и ввести:

   ```
   wsl -d Ubuntu -u root
   cd "/mnt/c/Users/islam/Desktop/Клиент-серверные технологии и их безопасность/ПР6_CICD_SAST_SCA"
   bash scripts/demo.sh prepare
   ```
2. В браузере заранее открыть вкладки:
   - https://github.com/is1am/cicd-sast-sca-pr6/actions — прогоны конвейера;
   - отчёт `report/Нуртазинов Ислам МСИБ-24 ПР6.pdf`.

Каждый этап ниже — одна команда; между шагами скрипт ждёт **Enter**, чтобы успеть объяснить.

## Сценарий

| № | Что показать | Команда / действие | Что сказать |
|---|---|---|---|
| 1 | Конвейер в GitHub Actions | вкладка Actions: прогон **#1 (v1)** — красный, последний — зелёный | «При каждом push запускаются SAST, SCA, поиск секретов, тесты, DAST и TLS gate. Уязвимая версия остановлена, исправленная проходит» |
| 2 | Pull requests Dependabot | вкладка Pull requests → Closed | «SCA сам предложил обновить уязвимые библиотеки» |
| 3 | Конвейер локально на уязвимой версии | `bash scripts/demo.sh scan-v1` | «Gitleaks нашёл секрет, Semgrep — 13 блокирующих находок, pip-audit — 45 CVE, 12 тестов упали → все 6 проверок FAIL» |
| 4 | То же на исправленной версии | `bash scripts/demo.sh scan-v2` | «0 находок, 0 CVE, 15/15 тестов → все PASS» |
| 5 | TLS «до» | `bash scripts/demo.sh tls-before` | «Сервер принимает TLS 1.0/1.1, шифры без PFS, нет HSTS — TLS gate FAILED» |
| 6 | TLS «после» | `bash scripts/demo.sh tls-after` | «Только TLS 1.2/1.3, TLS 1.0 отклонён alert protocol_version, HSTS есть — TLS gate OK» |
| 7 | Запуск мишеней | `bash scripts/demo.sh apps` | v1 на :5001, v2 на :5002, Juice Shop на :3000 |
| 8 | Атаки SQLi и IDOR | `bash scripts/demo.sh attack` | «v1: `admin' --` даёт токен администратора, UNION выдаёт хеши паролей, IDOR — чужой профиль. v2: 401 / пусто / 403. Juice Shop: `' OR 1=1--` — вход администратором» |
| 9 | OWASP ZAP (GUI) | `bash scripts/demo.sh zap`, затем открыть **http://localhost:8080/zap/** в браузере → «No, I do not want to persist» → Start → Enter в терминале | Вкладка **Alerts**: High «SQL Injection» в v1. **Sites** → localhost:5001 → api → users → GET:3 → Response — чужие данные; то же для 5002 — 403 |
| 10 | Код исправлений | в VS Code / GitHub: `git diff v1-vulnerable v2-fixed -- src/shop/app.py` | Параметризованные запросы, `require_role`, `can_access`, секрет из окружения, `yaml.safe_load` |
| 11 | Завершение | `bash scripts/demo.sh stop` | останавливает приложения, контейнеры и отключает сайт Nginx |

## Если что-то пошло не так

- **Нет интернета** — этапы 3–8 работают офлайн, кроме обновления баз уязвимостей pip-audit/Trivy (тогда показать сохранённые результаты в `evidence/v1_vulnerable` и `evidence/v2_fixed`).
- **Порт занят** — `bash scripts/demo.sh stop` и повторить этап.
- **ZAP долго грузится** — первый запуск Webswing занимает 30–60 с; можно показать скриншоты ZAP из отчёта (раздел 8).
- Все результаты, снимки и дампы уже лежат в `evidence/` и в отчёте — демонстрацию можно провести и по ним.

## Учётные записи стенда (вымышленные)

| Логин | Пароль | Роль |
|---|---|---|
| admin | Adm1n!Secure2026 | admin |
| aliya | Aliya#2026 | user |
| timur | Timur#2026 | user |
