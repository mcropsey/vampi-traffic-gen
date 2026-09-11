#!/usr/bin/env python3
"""
baseline_03_register_user.py — NORMAL baseline: register a new account.

POST /users/v1/register with username + password + email (NO admin field —
that's the "mass assignment" pattern, covered in vuln/). Creates a throwaway
account so re-runs are safe.
Run: python3 baseline_03_register_user.py [--config path/to/vampi_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: register a user")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)

    username = vc.rand_username("baseline")
    password = vc.rand_password()
    email = vc.rand_email(username)
    payload = {"username": username, "password": password, "email": email}
    r = requests.post(f"{base}/users/v1/register", json=payload,
                      headers={**vc.consumer_headers(3), "Content-Type": "application/json"}, timeout=tout)
    d = r.json() if r.status_code != 204 else {}
    print(f"baseline_03 register_user: HTTP {r.status_code} -> status={d.get('status')} as {username}")


if __name__ == "__main__":
    main()
