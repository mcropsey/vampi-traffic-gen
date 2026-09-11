#!/usr/bin/env python3
"""
baseline_07_list_books.py — NORMAL baseline: list all books (title + owner).

GET /books/v1 (public list). Returns book_title + owner for every book.
Teaches the baseline the expected read of the book directory.
Run: python3 baseline_07_list_books.py [--config path/to/vampi_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: list books")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)

    r = requests.get(f"{base}/books/v1", headers=vc.consumer_headers(7), timeout=tout)
    items = vc.as_list(r.json())
    names = [b.get("book_title") for b in items[:3]]
    print(f"baseline_07 list_books: HTTP {r.status_code} -> {len(items)} books (e.g. {', '.join(map(str, names))})")


if __name__ == "__main__":
    main()
