"""Write a realistic set of demo logs: a day of web traffic and application logs with a database incident in the middle.

    python scripts/demo_logs.py demo-logs          # about 60,000 lines
    python scripts/demo_logs.py demo-logs --scale 10
    logsift ingest demo-logs && logsift serve

The same seed always gives the same logs, so screenshots and timings can be compared.
"""

from __future__ import annotations

import argparse
import json
import random
import math
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

PATHS = ["/", "/api/orders", "/api/orders/{id}", "/api/users/{id}", "/api/cart", "/api/search?q=shoes", "/static/app.js",
         "/static/app.css", "/health", "/api/checkout", "/login"]
AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)", "curl/8.4.0", "kube-probe/1.29"]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("folder", type=Path)
    p.add_argument("--scale", type=float, default=1.0)
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args()
    rnd = random.Random(args.seed)
    args.folder.mkdir(parents=True, exist_ok=True)
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(hours=24)
    incident = (start + timedelta(hours=15), start + timedelta(hours=15, minutes=40))  # the database falls over

    def in_incident(t: datetime) -> bool:
        return incident[0] <= t < incident[1]

    access, app, worker = [], [], []
    t = start
    step = 3.0 / args.scale
    while t < end:
        t += timedelta(seconds=rnd.expovariate(1 / step))
        hour = t.hour
        if rnd.random() > 0.35 + 0.65 * (0.5 + 0.5 * math.sin((hour - 9) / 24 * 6.283)):
            continue  # quieter at night
        path = rnd.choice(PATHS).format(id=rnd.randint(1, 9999))
        status = 200
        duration = rnd.lognormvariate(-3.2, 0.6)
        if path.startswith("/api") and in_incident(t) and rnd.random() < 0.55:
            status, duration = rnd.choice([502, 503, 504]), rnd.uniform(5, 30)
        elif rnd.random() < 0.02:
            status = rnd.choice([404, 404, 401, 403, 429])
        elif rnd.random() < 0.002:
            status = 500
        method = "POST" if path in ("/api/checkout", "/api/cart", "/login") else "GET"
        ip = f"{rnd.choice([203, 198, 192])}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
        stamp = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        access.append(f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {rnd.randint(200, 90000)} "-" "{rnd.choice(AGENTS)}" {duration:.3f}')
        if path.startswith("/api"):
            rid = uuid.UUID(int=rnd.getrandbits(128)).hex[:12]
            base = {"time": t.isoformat().replace("+00:00", "Z"), "service": "api", "host": f"api-{rnd.randint(1, 3)}", "request_id": rid}
            if status >= 500:
                db = f"10.0.4.{rnd.randint(2, 30)}:5432"
                app.append(json.dumps({**base, "level": "error", "msg": f"Timeout after {rnd.randint(2900, 3100)}ms talking to {db}",
                                       "path": path, "status": status}))
            elif duration > 0.25:
                app.append(json.dumps({**base, "level": "warn", "msg": "slow query", "duration_ms": int(duration * 1000),
                                       "db": {"table": rnd.choice(["orders", "users", "carts"])}}))
            elif rnd.random() < 0.15:
                app.append(json.dumps({**base, "level": "info", "msg": "request served", "path": path, "status": status,
                                       "duration_ms": int(duration * 1000)}))
            if status == 500:
                app.append(json.dumps({**base, "level": "error", "msg": f"KeyError: 'sku' while pricing cart {rnd.randint(1, 9999)}"}))
                app.append("Traceback (most recent call last):")
                app.append('  File "/srv/api/pricing.py", line 118, in price_cart')
                app.append("    unit = catalog[item['sku']].price")
                app.append("KeyError: 'sku'")
        if rnd.random() < 0.08:
            local = t.astimezone()  # Python's logging writes local time with no zone, so the demo does too
            when = local.strftime("%Y-%m-%d %H:%M:%S,") + f"{local.microsecond // 1000:03d}"
            job = rnd.randint(10000, 99999)
            if in_incident(t) and rnd.random() < 0.6:
                worker.append(f"{when} - jobs.runner - ERROR - job {job} failed: could not connect to database after 3 attempts")
            elif rnd.random() < 0.03:
                worker.append(f"{when} - jobs.mailer - WARNING - retrying email to customer{job}@example.test (smtp 451)")
            else:
                kind = rnd.choice(["invoice", "thumbnail", "export", "reminder"])
                worker.append(f"{when} - jobs.runner - INFO - job {job} ({kind}) done in {rnd.randint(40, 4000)}ms")
    (args.folder / "nginx-access.log").write_text("\n".join(access) + "\n", encoding="utf-8")
    (args.folder / "api.jsonl").write_text("\n".join(app) + "\n", encoding="utf-8")
    (args.folder / "worker.log").write_text("\n".join(worker) + "\n", encoding="utf-8")
    print(f"Wrote {len(access) + len(app) + len(worker):,} lines to {args.folder}/")


if __name__ == "__main__":
    main()
