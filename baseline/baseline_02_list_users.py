#!/usr/bin/env python3
"""
baseline_02_list_users.py — NORMAL baseline: list all users (basic info).

GET /users/v1 (public list). Returns username + email for every account.
Teaches the baseline the expected read of the user directory.
Run: python3 baseline_02_list_users.py [--config path/to/vampi_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: list users")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)

    r = requests.get(f"{base}/users/v1", headers=vc.consumer_headers(2), timeout=tout)
    items = vc.as_list(r.json())
    names = [u.get("username") for u in items[:3]]
    print(f"baseline_02 list_users: HTTP {r.status_code} -> {len(items)} users (e.g. {', '.join(map(str, names))})")


if __name__ == "__main__":
    main()
