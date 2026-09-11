#!/usr/bin/env python3
"""
baseline_01_home_banner.py — NORMAL baseline: fetch the VAmPI home banner.

GET / (public). Returns the app banner + the `vulnerable` mode flag. Teaches
the baseline the expected shape of the root endpoint.
Run: python3 baseline_01_home_banner.py [--config path/to/vampi_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: home banner")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = vc.load_config(args.config)
    base = vc.base_url(cfg)
    tout = vc.timeout(cfg)

    r = requests.get(f"{base}/", headers=vc.consumer_headers(1), timeout=tout)
    d = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    print(f"baseline_01 home_banner: HTTP {r.status_code} -> message={d.get('message')!r} vulnerable={d.get('vulnerable')}")


if __name__ == "__main__":
    main()
