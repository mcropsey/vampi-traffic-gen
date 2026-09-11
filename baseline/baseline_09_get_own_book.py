#!/usr/bin/env python3
"""
baseline_09_get_own_book.py — NORMAL baseline: read own book + secret.

GET /books/v1/{own-book} (authenticated). Reads back a book the caller OWNS
(picks one from the list; creates one first if the user has none). This is the
legitimate version of the "read book by title" endpoint — the BOLA pattern
(other users' books) lives in vuln/.
Run: python3 baseline_09_get_own_book.py [--config path/to/vampi_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: read own book")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)
    u = vc.known_users(cfg)[0]
    username = u["username"]

    token = vc.login(base, username, u["password"], vc.consumer_headers(9), tout)
    if not token:
        print(f"baseline_09 get_own_book: FAILED login for {username}")
        return
    h = vc.auth_headers(token)

    # Find a book owned by this user; if none, create one so the read is "own".
    r = requests.get(f"{base}/books/v1", headers=h, timeout=tout)
    mine = [b for b in vc.as_list(r.json()) if b.get("user") == username]
    if mine:
        title = mine[0].get("book_title")
    else:
        title = vc.rand_book_title(username)
        requests.post(f"{base}/books/v1", json={"book_title": title, "secret": vc.rand_password()},
                      headers={**h, "Content-Type": "application/json"}, timeout=tout)

    r = requests.get(f"{base}/books/v1/{title}", headers=h, timeout=tout)
    d = r.json() if r.status_code != 204 else []
    owner = d[0].get("owner") if isinstance(d, list) and d else (d.get("owner") if isinstance(d, dict) else None)
    has_secret = (isinstance(d, dict) and "secret" in d) or (isinstance(d, list) and bool(d) and "secret" in d[0])
    print(f"baseline_09 get_own_book: HTTP {r.status_code} -> title={title} owner={owner} secret_present={has_secret}")


if __name__ == "__main__":
    main()
