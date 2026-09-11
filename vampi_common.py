#!/usr/bin/env python3
"""
vampi_common.py
===============
Shared helpers for the VAmPI traffic generators (vampi_traffic.py, the
*_cycle.py scripts, and the baseline/ + vuln/ challenge scripts).

Keeps config loading, known-user derivation, the login call, per-consumer
identity headers, JWT crafting, and run stats in one place so every script
behaves consistently.

VAmPI is a deliberately vulnerable "vulnerable-on-purpose" training API.
Point base_url at your own lab only — never at systems you don't own.

IMPORTANT — short-lived tokens:
    VAmPI issues JWTs that expire quickly (this instance: 60 s, iat->exp).
    There is no refresh endpoint. The helpers below therefore:
      * `login()`         — do one login, return the token (or None);
      * `fresh_token()`   — re-login on demand (use this before every batch of
                            authenticated calls in a long-running script);
      * `auth_get/put/post/delete()` — issue a call, and if the server answers
                            401 (token expired) re-login once and retry.
    Callers should treat 401 as "re-login and retry", never as "stop".

Dependencies:  pip install requests pyyaml
"""

import base64
import json
import os
import random
import string
import sys
import time
from typing import Any, Dict, List, Optional

import requests
import yaml


DEFAULT_CONFIG = "vampi_config.yaml"


# ── config loading ───────────────────────────────────────────────────────────
def load_config(path: str = DEFAULT_CONFIG) -> dict:
    if not os.path.exists(path):
        sys.exit(f"Config file not found: {path}\n"
                 f"Create one next to the scripts (see vampi_config.yaml).")
    with open(path) as f:
        return yaml.safe_load(f) or {}


def base_url(cfg: dict) -> str:
    return str((cfg.get("target") or {}).get("base_url", "http://localhost:5000")).rstrip("/")


def timeout(cfg: dict) -> float:
    return float((cfg.get("http") or {}).get("timeout", 10.0))


# ── response parsing (VAmPI's shapes are inconsistent across endpoints) ─────
def as_list(data: Any) -> List[Any]:
    """Return the list that an endpoint's response wraps, or [] if there is
    none. Handles VAmPI's mixed envelopes:
        /users/v1      -> {"users": [...]}
        /books/v1      -> {"Books": [...]}
        /books/v1/{t}  -> [...]            (a bare array)
        /me            -> {"data": {...}}  (not a list)
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("users", "Users", "Books", "books", "data", "items", "results"):
            if k in data and isinstance(data[k], list):
                return data[k]
    return []


def count_items(data: Any) -> int:
    return len(as_list(data))


def known_users(cfg: dict) -> List[Dict[str, str]]:
    """Return [{username, password, email}] for the configured known lab users.

    VAmPI seeds name1/pass1, name2/pass2, ... and an admin account. The admin
    password is pass1 on this instance (not admin123). These are the
    authenticated identities for the findings phase.
    """
    ku = cfg.get("known_users") or {}
    users = ku.get("users") or [
        {"username": "name1", "password": "pass1", "email": "mail1@mail.com"},
        {"username": "name2", "password": "pass2", "email": "mail2@mail.com"},
        {"username": "admin", "password": "pass1", "email": "admin@mail.com"},
    ]
    out = []
    for u in users:
        name = u.get("username")
        out.append({
            "username": name,
            "password": u.get("password"),
            "email": u.get("email") or f"{name}@mail.com",
        })
    return out


def known_usernames(cfg: dict) -> List[str]:
    return [u["username"] for u in known_users(cfg)]


def brute_target(cfg: dict) -> str:
    return str((cfg.get("findings") or {}).get("brute_target", "locked-target"))


# ── consumer identity surface ────────────────────────────────────────────────
UAS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/124.0",
    "VAmPI-Client/1.0 (Android 14; Pixel 8)",
    "VAmPI-Client/1.0 (iOS 17.4; iPhone15,3)",
    "PostmanRuntime/7.37.0",
    "python-requests/2.31.0",
    "okhttp/4.12.0",
]


def consumer_headers(idx: int) -> Dict[str, str]:
    """Each consumer gets a distinct identity surface. Which of these the sensor
    actually counts as a 'consumer' depends on its config (source IP / token sub
    / api key) — vary all of them so at least one dimension lands."""
    octet_a = (idx // 254) % 254 + 1
    octet_b = idx % 254 + 1
    return {
        "User-Agent": random.choice(UAS),
        "X-Forwarded-For": f"10.{octet_a}.{octet_b}.{random.randint(2, 250)}",
        "X-Api-Client": f"client-{idx:05d}",
    }


def rand_username(tag: str = "user") -> str:
    n = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{tag}_{n}"


def rand_email(username: str) -> str:
    return f"{username}@mail.com"


def rand_password() -> str:
    return "GoodPass" + str(random.randint(1000, 9999)) + "!"


def rand_book_title(tag: str = "book") -> str:
    n = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{tag}_{n}"


def auth_headers(token: str, extra: Optional[dict] = None) -> Dict[str, str]:
    h = dict(extra or {})
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


# ── auth ─────────────────────────────────────────────────────────────────────
def login(base: str, username: str, password: str, hdrs: Optional[dict] = None,
          timeout: float = 10.0) -> Optional[str]:
    """POST /users/v1/login -> auth_token (or None on any failure).

    VAmPI's token expires fast, so this is a one-shot login: call it again any
    time you need a fresh token (or use auth_* below, which re-login on 401).
    """
    url = f"{base}/users/v1/login"
    payload = {"username": username, "password": password}
    h = dict(hdrs or {})
    h["Content-Type"] = "application/json"
    try:
        r = requests.post(url, json=payload, headers=h, timeout=timeout)
        data = r.json()
    except Exception:
        return None
    return data.get("auth_token") or data.get("token")


def token_claims(token: str) -> dict:
    """Base64url-decode a JWT's payload segment into a dict (no verification).
    VAmPI tokens carry {"exp": ..., "iat": ..., "sub": <username>} — `sub` is
    the username, so this is a reliable identity source."""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        obj = json.loads(base64.urlsafe_b64decode(seg))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def token_sub(token: str) -> Optional[str]:
    """The username (JWT `sub` claim) — VAmPI's identity is the username, not
    an opaque numeric id like Juice Shop's bid."""
    return token_claims(token).get("sub")


def get_tokens(cfg: dict) -> Dict[str, str]:
    """Log in each known lab user once; return {username: token}."""
    base = base_url(cfg)
    tout = timeout(cfg)
    users = known_users(cfg)
    tokens = {}
    for i, u in enumerate(users):
        tok, last_code = "", None
        for _ in range(4):                     # retry transient non-200s
            tok = login(base, u["username"], u["password"], consumer_headers(1000 + i), tout)
            last_code = "ok" if tok else "fail"
            if tok:
                break
            time.sleep(1.5)
        tokens[u["username"]] = tok
        bump("auth.login", last_code)
        if not tok:
            print(f"[auth]   ! no token for {u['username']} (last status {last_code})")
    ok = sum(1 for t in tokens.values() if t)
    print(f"[auth] obtained tokens for {ok}/{len(users)} known users")
    return tokens


# ── JWT crafting (no signing key needed; sensor inspects header+claims) ──────
def b64url(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(sub: str, alg: str = "none", exp_delta: int = 3600, sig: str = "fakesig") -> str:
    """Build a raw JWT. `alg=none` yields an unsigned token (empty signature
    segment); other algs get a bogus signature. Mirrors VAmPI's claim shape
    (sub/iat/exp) for the bad-token findings."""
    header = {"alg": alg, "typ": "JWT"}
    now = int(time.time())
    payload = {"sub": sub, "iat": now, "exp": now + exp_delta}
    token = f"{b64url(header)}.{b64url(payload)}"
    if alg == "none":
        return token + "."
    return f"{token}.{base64.urlsafe_b64encode(sig.encode()).rstrip(b'=').decode()}"


# ── run stats / formatting ───────────────────────────────────────────────────
stats: Dict[str, Dict[str, int]] = {}


def bump(key: str, code: Any) -> None:
    stats.setdefault(key, {})
    stats[key][code] = stats[key].get(code, 0) + 1


def fmt_dur(seconds: float) -> str:
    """Human-readable duration, e.g. '1h 03m 07s' / '4m 12s' / '9s'."""
    m, s = divmod(int(round(seconds)), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def print_summary(timings: Dict[str, float], total: float) -> None:
    print("\n--- summary ---")
    for k in sorted(stats):
        print(f"{k}: {stats[k]}")
    print("\n--- timing ---")
    for phase, dur in timings.items():
        print(f"{phase}: {fmt_dur(dur)} ({dur:.1f}s)")
    print(f"total run time: {fmt_dur(total)} ({total:.1f}s)")
