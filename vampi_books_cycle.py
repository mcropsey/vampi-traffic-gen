#!/usr/bin/env python3
"""
Generate NORMAL traffic for VAmPI book-management flows.

Flow per user (repeated for N cycles):
  1. Login
  2. List all books (GET /books/v1)
  3. Add own book (POST /books/v1)
  4. Read own book + secret (GET /books/v1/{self-book})
  5. Discard token

This teaches an API security solution the expected behaviour when users store
and retrieve their OWN books. Only the caller's OWN book is read (no BOLA).

NOTE: VAmPI issues short-lived JWTs (this instance: 60 s); the script re-logins
once per user per cycle, and the per-user flow is a few quick calls.
"""

import argparse
import time

import requests

import vampi_common as vc


def list_books(base, hdrs, tout):
    """GET /books/v1 — list all books (title + owner)."""
    try:
        r = requests.get(f"{base}/books/v1", headers=hdrs, timeout=tout)
        r.raise_for_status()
        return vc.as_list(r.json())
    except requests.RequestException as e:
        print(f"  [!] list_books failed: {e}")
        return []


def add_book(base, token, title, secret, hdrs, tout):
    """POST /books/v1 — add own book with a secret."""
    try:
        r = requests.post(f"{base}/books/v1", json={"book_title": title, "secret": secret},
                          headers={**hdrs, "Content-Type": "application/json"}, timeout=tout)
        return r.status_code
    except requests.RequestException as e:
        print(f"  [!] add_book({title}) failed: {e}")
        return "err"


def get_book(base, token, title, hdrs, tout):
    """GET /books/v1/{title} — read own book + secret."""
    try:
        r = requests.get(f"{base}/books/v1/{title}", headers=hdrs, timeout=tout)
        if r.status_code == 200:
            data = r.json()
            return (len(data) if isinstance(data, list) else 1)
        return None
    except requests.RequestException as e:
        print(f"  [!] get_book({title}) failed: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Generate normal (legitimate) book-management traffic for VAmPI")
    parser.add_argument("--config", default="vampi_config.yaml",
                        help="Path to config file (default: vampi_config.yaml)")
    parser.add_argument("--cycles", type=int, default=1,
                        help="Number of full cycles through all known users (default: 1)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay (seconds) between major steps (default: 0.5)")
    parser.add_argument("--timeout", type=float, default=12.0,
                        help="HTTP timeout in seconds (default: 12)")
    args = parser.parse_args()

    cfg = vc.load_config(str(args.config))
    base = vc.base_url(cfg)
    tout = args.timeout
    users = vc.known_users(cfg)

    print(f"Target  : {base}")
    print(f"Users   : {len(users)}")
    print(f"Cycles  : {args.cycles}")
    print(f"Purpose : NORMAL traffic only (list books, add own book, read own book)")
    print("-" * 60)

    for cycle in range(1, args.cycles + 1):
        print(f"\n=== Cycle {cycle}/{args.cycles} ===")
        for idx, u in enumerate(users):
            username = u["username"]
            print(f"\nUser: {username}")

            # 1. Login (fresh token each turn — tokens are short-lived)
            token = vc.login(base, username, u["password"], vc.consumer_headers(idx), tout)
            if not token:
                print("  Skipping (login failed)")
                continue
            hdrs = vc.auth_headers(token, vc.consumer_headers(idx))
            time.sleep(args.delay * 0.4)

            # 2. List all books
            books = list_books(base, hdrs, tout)
            print(f"  Listed {len(books)} books")
            time.sleep(args.delay * 0.3)

            # 3. Add own book (unique title so re-runs don't collide)
            title = vc.rand_book_title(f"{username}")
            secret = vc.rand_password()
            code = add_book(base, token, title, secret, hdrs, tout)
            print(f"  Added own book '{title}' -> HTTP {code}")
            time.sleep(args.delay * 0.3)

            # 4. Read own book + secret
            got = get_book(base, token, title, hdrs, tout)
            if got is not None:
                print(f"  Read own book '{title}' ({got} record(s))")
            else:
                print("  Could not read own book back")

            # 5. Discard token (JWT — just drop it)
            time.sleep(args.delay)

    print("\nDone — normal book-management traffic generated.")


if __name__ == "__main__":
    main()
