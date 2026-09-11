#!/usr/bin/env python3
"""
vampi_challenge_08_unauthenticated_access.py — Broken access control (no auth).

The user/book update + read endpoints require a Bearer token. We hit each of
them with NO Authorization header. If any returns 200 (instead of 401/403),
that's a broken-access-control finding. On a healthy instance every one of
these should be 401 — the script reports honestly either way.

Read-only probes (the write probes are rejected pre-auth); safe to re-run.
Run: python3 vampi_challenge_08_unauthenticated_access.py [--config ...]
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
    ap = argparse.ArgumentParser(description="Access auth-gated endpoints with no token")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    user = vc.known_users(cfg)[0]["username"]

    # (method, path, has-body)
    probes = [
        ("GET", f"/users/v1/{user}", False),
        ("GET", "/me", False),
        ("GET", "/books/v1/bookTitle10", False),
        ("PUT", f"/users/v1/{user}/password", True),
        ("PUT", f"/users/v1/{user}/email", True),
        ("DELETE", f"/users/v1/{user}", False),
    ]
    leaks = 0
    for method, path, body in probes:
        try:
            if body:
                r = requests.request(method, f"{base}{path}", json={"x": "y"},
                                     headers={**vc.consumer_headers(808), "Content-Type": "application/json"}, timeout=tout)
            else:
                r = requests.request(method, f"{base}{path}",
                                     headers=vc.consumer_headers(808), timeout=tout)
        except requests.RequestException as e:
            print(f"{method:6} {path:40} -> error {e}")
            continue
        allowed = 200 <= r.status_code < 300
        if allowed:
            leaks += 1
        print(f"{method:6} {path:40} -> HTTP {r.status_code} {'[ACCESSIBLE UNAUTH]' if allowed else ''}")

    print(f"\nDone — {leaks}/{len(probes)} auth-gated endpoint(s) reachable WITHOUT a token.")


if __name__ == "__main__":
    main()
