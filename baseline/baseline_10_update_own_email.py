#!/usr/bin/env python3
"""
baseline_10_update_own_email.py — NORMAL baseline: update own email.

PUT /users/v1/{own-username}/email (authenticated) with the caller's own
username. This is the legitimate self-service email change — the BOLA pattern
(changing OTHER users' email/password) lives in vuln/.
Run: python3 baseline_10_update_own_email.py [--config path/to/vampi_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: update own email")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    u = vc.known_users(cfg)[0]
    username = u["username"]

    token = vc.login(base, username, u["password"], vc.consumer_headers(10), tout)
    if not token:
        print(f"baseline_10 update_own_email: FAILED login for {username}")
        return

    # Set a stable, valid lab address (idempotent, does not break the account).
    email = f"{username}@mail.com"
    r = requests.put(f"{base}/users/v1/{username}/email", json={"email": email},
                     headers={**vc.auth_headers(token), "Content-Type": "application/json"}, timeout=tout)
    print(f"baseline_10 update_own_email: HTTP {r.status_code} -> {username} email={email}")


if __name__ == "__main__":
    main()
