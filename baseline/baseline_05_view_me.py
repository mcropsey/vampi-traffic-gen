#!/usr/bin/env python3
"""
baseline_05_view_me.py — NORMAL baseline: view own profile.

GET /me with a valid token. Returns the caller's admin flag, email, username.
Teaches the baseline the authenticated self-read.
Run: python3 baseline_05_view_me.py [--config path/to/vampi_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: view own profile")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    u = vc.known_users(cfg)[0]

    token = vc.login(base, u["username"], u["password"], vc.consumer_headers(5), tout)
    if not token:
        print(f"baseline_05 view_me: FAILED login for {u['username']}")
        return

    r = requests.get(f"{base}/me", headers=vc.auth_headers(token), timeout=tout)
    d = r.json() if r.status_code != 204 else {}
    data = d.get("data", {}) if isinstance(d, dict) else {}
    print(f"baseline_05 view_me: HTTP {r.status_code} -> {data.get('username')} <{data.get('email')}> admin={data.get('admin')}")


if __name__ == "__main__":
    main()
