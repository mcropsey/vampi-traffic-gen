#!/usr/bin/env python3
"""
baseline_04_login_user.py — NORMAL baseline: log in a known user.

POST /users/v1/login with a known lab username + password. Reports that a JWT
was issued (truncated) and decodes its `sub`/expiry so the baseline learns the
token shape (VAmPI tokens are short-lived — note the exp-iat delta).
Run: python3 baseline_04_login_user.py [--config path/to/vampi_config.yaml]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import vampi_common as vc


def find_config():
    if os.path.exists("vampi_config.yaml"):
        return "vampi_config.yaml"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vampi_config.yaml")


def main():
    ap = argparse.ArgumentParser(description="NORMAL baseline: login a known user")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    u = vc.known_users(cfg)[0]

    token = vc.login(base, u["username"], u["password"], vc.consumer_headers(4), tout)
    if not token:
        print(f"baseline_04 login_user: FAILED for {u['username']}")
        return
    claims = vc.token_claims(token)
    delta = claims.get("exp", 0) - claims.get("iat", 0)
    print(f"baseline_04 login_user: OK for {u['username']} -> token {token[:24]}... sub={claims.get('sub')} exp-iat={delta}s")


if __name__ == "__main__":
    main()
