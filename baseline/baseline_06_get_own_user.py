#!/usr/bin/env python3
"""
baseline_06_get_own_user.py — NORMAL baseline: fetch own user record.

GET /users/v1/{own-username}. Returns the caller's own username + email.
Teaches the baseline the expected read of a SINGLE (own) user object.
Run: python3 baseline_06_get_own_user.py [--config path/to/vampi_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: get own user")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    u = vc.known_users(cfg)[0]
    username = u["username"]

    r = requests.get(f"{base}/users/v1/{username}", headers=vc.consumer_headers(6), timeout=tout)
    d = r.json() if r.status_code != 204 else {}
    print(f"baseline_06 get_own_user: HTTP {r.status_code} -> {d.get('username')} <{d.get('email')}>")


if __name__ == "__main__":
    main()
