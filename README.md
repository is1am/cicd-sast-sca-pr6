# ПР6 — CI/CD Security Pipeline: SAST и SCA в GitHub Actions / GitLab CI

Практическая работа №6 «Настройка TLS/SSL. Анализ OWASP Top 10» по дисциплине
«Клиент-серверные технологии и их безопасность». Тема проекта — автоматическое
сканирование исходного кода (SAST) и зависимостей (SCA) в конвейере CI/CD.

Учебный объект — REST API **ENU Lab Shop** (Python/Flask, SQLite). История git:

| Тег | Состояние | Конвейер |
| --- | --- | --- |
| `v1-vulnerable` | SQLi, IDOR, внедрение команд, секрет в коде, MD5, yaml.load, debug, устаревшие зависимости | падает |
| `v2-fixed` | исправления по результатам SAST/SCA и security-тестов | проходит |

## Что где лежит

| Путь | Назначение |
| --- | --- |
| `src/shop/app.py`, `src/shop/db.py` | приложение |
| `tests/test_security.py` | 15 регрессионных security-тестов (SQLi, IDOR, RBAC, YAML, заголовки) |
| `.github/workflows/security-pipeline.yml` | GitHub Actions: Gitleaks, Semgrep, Bandit, CodeQL, pip-audit, Trivy, Dependency Review, pytest, ZAP, TLS gate |
| `.github/dependabot.yml` | автоматические PR с обновлениями зависимостей |
| `.gitlab-ci.yml` | тот же конвейер для GitLab CI (шаблоны SAST / Dependency / Secret Detection + свои gate-задания) |
| `.semgrep/rules.yml` | собственные правила SAST (SQLi, секрет, IDOR, debug, трассировка) |
| `.gitleaksignore`, `.zap/rules.tsv` | точечные исключения Gitleaks и правила ZAP baseline |
| `nginx/tls-weak.conf`, `nginx/tls-hardened.conf` | TLS-конфигурации «до» и «после» |
| `scripts/run_scans.sh` | локальный прогон всех проверок конвейера |
| `scripts/tls_gate.sh` | TLS gate для CI (протоколы, шифры, HSTS) |
| `scripts/tls_lab.sh`, `scripts/owasp_zap_lab.py` | лабораторные части 1–3 (OpenSSL, testssl.sh, tshark, ZAP) |
| `evidence/` | результаты всех прогонов |

## Демонстрация

Пошаговый сценарий — в [DEMO.md](DEMO.md), все этапы запускаются скриптом `scripts/demo.sh`
(`prepare`, `scan-v1`, `scan-v2`, `tls-before`, `tls-after`, `apps`, `attack`, `zap`, `stop`).

## Запуск

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
export SHOP_SECRET_KEY=$(openssl rand -hex 32)
python -m src.shop.app          # http://127.0.0.1:5000
pytest -v
```

Учётные записи стенда: `admin / Adm1n!Secure2026`, `aliya / Aliya#2026`,
`timur / Timur#2026`, `dana / Dana#2026` (вымышленные данные).

## Локальная проверка (как в CI)

```bash
TOOLS_BIN=/path/to/venv/bin APP_PY=python3 scripts/run_scans.sh evidence/scan
```
