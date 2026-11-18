"""Локальная проверка .gitlab-ci.yml: каждое собственное задание запускается в своём Docker-образе
с теми же командами script, что выполнит GitLab Runner (аналог `gitlab-runner exec docker`).
Задания из шаблонов GitLab (sast, dependency_scanning, secret_detection) требуют инфраструктуры
GitLab и здесь не запускаются.
Использование: python3 gitlab_jobs_local.py <каталог-репозитория> <файл-журнала>
"""
import subprocess
import sys

import yaml

repo, logfile = sys.argv[1], sys.argv[2]
cfg = yaml.safe_load(open(f"{repo}/.gitlab-ci.yml", encoding="utf-8"))
skip = {"stages", "include", "variables", "sast", "dependency_scanning", "secret_detection"}
results = []
with open(logfile, "w", encoding="utf-8") as log:
    for name, job in cfg.items():
        if name in skip or not isinstance(job, dict) or "script" not in job:
            continue
        img = job["image"]
        entry = []
        if isinstance(img, dict):
            if img.get("entrypoint") == [""]:
                entry = ["--entrypoint", ""]
            img = img["name"]
        env = []
        for k, v in {**cfg.get("variables", {}), **job.get("variables", {})}.items():
            env += ["-e", f"{k}={v}"]
        script = "set -e\n" + "\n".join(job["script"])
        cmd = ["docker", "run", "--rm", "--network", "host", *entry, *env, "-v", f"{repo}:/builds/pr6",
               "-w", "/builds/pr6", "-u", "0", img, "sh", "-c", script]
        log.write(f"\n===== job {name} (stage {job.get('stage')}, image {img}) =====\n")
        log.flush()
        p = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
        status = "passed" if p.returncode == 0 else f"failed (exit {p.returncode})"
        log.write(f"===== job {name}: {status}\n")
        results.append((name, job.get("stage"), img, status))
for r in results:
    print(f"{r[0]:<16} {r[1]:<9} {r[2]:<28} {r[3]}")
