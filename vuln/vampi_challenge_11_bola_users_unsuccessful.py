#!/usr/bin/env python3
"""
vampi_challenge_11_bola_users_unsuccessful.py — BOLA on users (attempted, unsuccessful).

Same flow as challenge 02: a legitimate user reads their OWN record (baseline),
then requests other users' records with the same valid session. The difference:
the usernames here are random guesses that don't exist in the roster, so the
API rejects every one (404 "User not found") and no foreign record is ever
returned. This is the "attacker knows the technique but cannot find a valid
foreign id" pattern — the attempt traffic is identical, the access fails.
Run: python3 vampi_challenge_11_bola_users_unsuccessful.py [--config ...]
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
    ap = argparse.ArgumentParser(description="BOLA on other users' records (unsuccessful attempt)")
    ap.add_argument("--config", default=find_config())
    ap.add_argument("--count", type=int, default=5, help="number of guessed usernames")
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    u = vc.known_users(cfg)[0]
    own = u["username"]

    token = vc.login(base, own, u["password"], vc.consumer_headers(814), tout)
    if not token:
        print("login failed, skipping")
        return
    h = vc.auth_headers(token)

    r = requests.get(f"{base}/users/v1/{own}", headers=h, timeout=tout)
    print(f"baseline  GET /users/v1/{own} (own) -> HTTP {r.status_code}")

    guesses = [vc.rand_username() for _ in range(args.count)]
    exposed = 0
    for i, name in enumerate(guesses, 1):
        r = requests.get(f"{base}/users/v1/{name}", headers=h, timeout=tout)
        foreign = r.status_code == 200 and name != own
        if foreign:
            exposed += 1
        print(f"bola      GET /users/v1/{name} (guessed {i}/{args.count}) -> HTTP {r.status_code} {'[EXPOSED]' if foreign else ''}")

    if exposed:
        print(f"\nDone — {exposed} foreign user record(s) readable by a non-owner token. (BOLA succeeded — unexpected for this script.)")
    else:
        print(f"\nDone — {args.count} guessed username(s) probed, 0 readable by a non-owner token. BOLA attempt unsuccessful.")


if __name__ == "__main__":
    main()
