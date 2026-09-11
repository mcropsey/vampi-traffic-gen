#!/usr/bin/env python3
"""
Generate NORMAL traffic for VAmPI user-management flows.

Flow per user (repeated for N cycles):
  1. Login
  2. View own profile (GET /me)
  3. List all users (GET /users/v1)
  4. View own record (GET /users/v1/{self})
  5. Update own email (PUT /users/v1/{self}/email)
  6. Discard token

This teaches an API security solution the expected behaviour when users manage
their own account. Only the caller's OWN resources are touched (no BOLA).

NOTE: VAmPI issues short-lived JWTs (this instance: 60 s); the script re-logins
once per user per cycle, and the per-user flow is a few quick calls.
"""

import argparse
import sys
import time

import requests

import vampi_common as vc


def view_me(base, token, hdrs, tout):
    """GET /me — own profile."""
    try:
        r = requests.get(f"{base}/me", headers=hdrs, timeout=tout)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        print(f"  [!] view_me failed: {e}")
        return None


def list_users(base, hdrs, tout):
    """GET /users/v1 — list all users (basic info)."""
    try:
        r = requests.get(f"{base}/users/v1", headers=hdrs, timeout=tout)
        r.raise_for_status()
        return vc.as_list(r.json())
    except requests.RequestException as e:
        print(f"  [!] list_users failed: {e}")
        return []


def get_own_user(base, token, username, hdrs, tout):
    """GET /users/v1/{self} — own record."""
    try:
        r = requests.get(f"{base}/users/v1/{username}", headers=hdrs, timeout=tout)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        print(f"  [!] get_own_user({username}) failed: {e}")
        return None


def update_own_email(base, token, username, email, hdrs, tout):
    """PUT /users/v1/{self}/email — update own email."""
    try:
        r = requests.put(f"{base}/users/v1/{username}/email",
                         json={"email": email},
                         headers={**hdrs, "Content-Type": "application/json"}, timeout=tout)
        return r.status_code
    except requests.RequestException as e:
        print(f"  [!] update_own_email({username}) failed: {e}")
        return "err"


def main():
    parser = argparse.ArgumentParser(
        description="Generate normal (legitimate) user-management traffic for VAmPI")
    parser.add_argument("--config", default="vampi_config.yaml",
                        help="Path to config file (default: vampi_config.yaml)")
    parser.add_argument("--cycles", type=int, default=1,
                        help="Number of full cycles through all known users (default: 1)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay (seconds) between major steps (default: 0.5)")
    parser.add_argument("--timeout", type=float, default=12.0,
                        help="HTTP timeout in seconds (default: 12)")
    args = parser.parse_args()

    cfg = vc.load_config(str(args.config))
    base = vc.base_url(cfg)
    tout = args.timeout
    users = vc.known_users(cfg)

    print(f"Target  : {base}")
    print(f"Users   : {len(users)}")
    print(f"Cycles  : {args.cycles}")
    print(f"Purpose : NORMAL traffic only (own profile, list users, own record, own email)")
    print("-" * 60)

    for cycle in range(1, args.cycles + 1):
        print(f"\n=== Cycle {cycle}/{args.cycles} ===")
        for idx, u in enumerate(users):
            username = u["username"]
            print(f"\nUser: {username}")

            # 1. Login (fresh token each turn — tokens are short-lived)
            token = vc.login(base, username, u["password"], vc.consumer_headers(idx), tout)
            if not token:
                print("  Skipping (login failed)")
                continue
            hdrs = vc.auth_headers(token, vc.consumer_headers(idx))
            time.sleep(args.delay * 0.4)

            # 2. View own profile
            me = view_me(base, token, hdrs, tout)
            print(f"  Own profile: {me.get('data', {}).get('username') if isinstance(me, dict) else me}")
            time.sleep(args.delay * 0.3)

            # 3. List all users
            all_users = list_users(base, hdrs, tout)
            print(f"  Listed {len(all_users)} users")
            time.sleep(args.delay * 0.3)

            # 4. View own record
            own = get_own_user(base, token, username, hdrs, tout)
            if isinstance(own, dict):
                print(f"  Own record: {own.get('username')} <{own.get('email')}>")
            else:
                print("  Could not read own record")
            time.sleep(args.delay * 0.3)

            # 5. Update own email (idempotent — sets a stable lab address)
            code = update_own_email(base, token, username, f"{username}@mail.com", hdrs, tout)
            print(f"  Updated own email -> HTTP {code}")

            # 6. Discard token (JWT — just drop it)
            time.sleep(args.delay)

    print("\nDone — normal user-management traffic generated.")


if __name__ == "__main__":
    main()
