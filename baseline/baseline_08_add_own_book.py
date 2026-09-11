#!/usr/bin/env python3
"""
baseline_08_add_own_book.py — NORMAL baseline: add a personal book.

POST /books/v1 (authenticated) with a book_title + secret. Creates a throwaway
book so re-runs are safe. Teaches the baseline the expected write.
Run: python3 baseline_08_add_own_book.py [--config path/to/vampi_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: add own book")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    u = vc.known_users(cfg)[0]

    token = vc.login(base, u["username"], u["password"], vc.consumer_headers(8), tout)
    if not token:
        print(f"baseline_08 add_own_book: FAILED login for {u['username']}")
        return

    title = vc.rand_book_title("baseline")
    secret = vc.rand_password()
    r = requests.post(f"{base}/books/v1", json={"book_title": title, "secret": secret},
                      headers={**vc.auth_headers(token), "Content-Type": "application/json"}, timeout=tout)
    d = r.json() if r.status_code != 204 else {}
    print(f"baseline_08 add_own_book: HTTP {r.status_code} -> status={d.get('status')} title={title}")


if __name__ == "__main__":
    main()
