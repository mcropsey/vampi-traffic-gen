#!/usr/bin/env python3
"""
vampi_discovery.py — API discovery for VAMPI (github.com/erev0s/VAMPI)

Only run this against a VAMPI instance you own / are authorised to test.
VAMPI is an intentionally vulnerable practice target for API security learning.

What it does, in three passes:
  1. SPEC     : pull the OpenAPI/Swagger spec and list every documented op.
  2. PROBE    : brute a wordlist of common API paths, report status codes.
  3. LIVE     : register + log in, then actually call every known endpoint
                (spec-derived + built-in map) and record status + response shape.

Target URLs come from config.json (base_url + path lists). Edit that file to
point at a different host; the CLI can still override per-run.

Usage:
  python3 vampi_discovery.py                         # reads config.json
  python3 vampi_discovery.py -c other.json           # use a different config file
  python3 vampi_discovery.py -u http://TARGET:5000   # override base_url for this run
  python3 vampi_discovery.py -u http://TARGET:5000 --token eyJ...   # reuse a token
  python3 vampi_discovery.py --no-live               # spec + probe only, no writes
  python3 vampi_discovery.py --json out.json         # dump full results to JSON

Requires: requests  (pip install -r requirements.txt)
"""

import argparse
import json
import os
import string
import random
import sys
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    sys.exit("Missing dependency. Run: pip install requests")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = "config.json"

# Fallbacks used only if a key is missing from the config file.
DEFAULT_BASE = "https://vampi.cropseyit.com"
TIMEOUT = 8

# Candidate locations for the OpenAPI / Swagger document.
SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/api-docs", "/api-docs.json", "/v2/api-docs", "/v3/api-docs",
    "/docs", "/ui/", "/swagger-ui/", "/redoc",
    "/spec", "/api/spec",
]

# Common API paths to probe blind (VAMPI-flavoured + generic).
PROBE_PATHS = [
    "/", "/createdb", "/me", "/health", "/status", "/version",
    "/users", "/users/v1", "/users/v1/_debug", "/users/v1/login",
    "/users/v1/register", "/users/v1/admin",
    "/books", "/books/v1", "/book", "/api", "/api/v1", "/api/v2",
    "/admin", "/debug", "/login", "/register", "/auth", "/token",
    "/products", "/orders", "/config", "/.env", "/robots.txt",
]


def load_config(path):
    """Load base_url / timeout / path lists from a JSON config file.

    Missing file or missing keys fall back to the built-in defaults above.
    Returns a dict with keys: base_url, timeout, spec_paths, probe_paths.
    """
    cfg = {
        "base_url": DEFAULT_BASE,
        "timeout": TIMEOUT,
        "spec_paths": SPEC_PATHS,
        "probe_paths": PROBE_PATHS,
    }
    if path and os.path.isfile(path):
        try:
            with open(path) as f:
                data = json.load(f)
            for k in cfg:
                if data.get(k):
                    cfg[k] = data[k]
            print(f"  [+] config loaded: {path}")
        except (ValueError, OSError) as e:
            print(f"  [-] could not read config {path} ({e}); using defaults")
    elif path and path != DEFAULT_CONFIG:
        print(f"  [-] config file not found: {path}; using defaults")
    return cfg

# Built-in VAMPI endpoint map — the ground truth for the LIVE pass.
# {method} and {path} are formatted with runtime values.
#
# NOTE: /createdb, register and login are deliberately NOT in this list. They
# are handled explicitly at the top of live() in the correct order. /createdb
# resets the demo database, so exercising it here (after we register our
# throwaway user) would delete that user out from under the rest of the pass
# and make every {username} call 404/500. register/login are likewise already
# performed before the loop, so re-issuing them here just sent empty-body noise.
VAMPI_ENDPOINTS = [
    ("GET",    "/",                              "home / vulnerable-mode banner",      False),
    ("GET",    "/me",                            "current logged-in user (needs token)", True),
    ("GET",    "/users/v1",                      "list all users (usernames)",         False),
    ("GET",    "/users/v1/_debug",               "list all users WITH passwords",      False),
    ("GET",    "/users/v1/{username}",           "get a single user by username",      False),
    ("DELETE", "/users/v1/{username}",           "delete a user (admin only)",         True),
    ("PUT",    "/users/v1/{username}/email",     "update a user's email",              True),
    ("PUT",    "/users/v1/{username}/password",  "update a user's password",           True),
    ("GET",    "/books/v1",                      "list all books",                     True),
    ("POST",   "/books/v1",                      "add a book",                         True),
    ("GET",    "/books/v1/{title}",              "get one book by title",              True),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def rand(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def shape(resp):
    """Compact description of a response body."""
    ct = resp.headers.get("content-type", "")
    # 204 No Content (and other genuinely empty bodies) carry no payload to
    # parse — report them as "empty" instead of "json(unparseable)".
    if resp.status_code == 204 or not (resp.content or b"").strip():
        return "empty"
    if "json" in ct:
        try:
            data = resp.json()
            if isinstance(data, dict):
                return "json{" + ",".join(list(data.keys())[:8]) + "}"
            if isinstance(data, list):
                inner = ""
                if data and isinstance(data[0], dict):
                    inner = "{" + ",".join(list(data[0].keys())[:6]) + "}"
                return f"json[{len(data)}]{inner}"
            return f"json:{type(data).__name__}"
        except ValueError:
            return "json(unparseable)"
    body = resp.text or ""
    return f"{ct.split(';')[0] or 'text'}:{len(body)}b"

def line(method, path, resp, note=""):
    code = resp.status_code if resp is not None else "ERR"
    sh = shape(resp) if resp is not None else note
    print(f"  {str(code):>4}  {method:<6} {path:<34} {sh}")

def req(session, method, url, **kw):
    try:
        return session.request(method, url, timeout=TIMEOUT, **kw)
    except requests.RequestException as e:
        print(f"  ERR   {method:<6} {url}  ({e.__class__.__name__})")
        return None

# ---------------------------------------------------------------------------
# Pass 1 — OpenAPI / Swagger spec
# ---------------------------------------------------------------------------

def discover_spec(session, base, results, spec_paths):
    print("\n=== [1] OpenAPI / Swagger spec ===")
    spec = None
    for p in spec_paths:
        url = urljoin(base, p)
        r = req(session, "GET", url)
        if r is None:
            continue
        ct = r.headers.get("content-type", "")
        looks_spec = r.status_code == 200 and (
            "openapi" in r.text[:400].lower() or "swagger" in r.text[:400].lower()
        )
        if looks_spec and ("json" in ct or r.text.strip().startswith("{")):
            try:
                spec = r.json()
                print(f"  [+] spec found: {p}")
            except ValueError:
                pass
        elif r.status_code == 200:
            print(f"  [200] {p}  ({ct.split(';')[0]}) — reachable, not parsed as JSON spec")

    ops = []
    if spec and isinstance(spec.get("paths"), dict):
        for path, methods in spec["paths"].items():
            for m, meta in (methods or {}).items():
                if m.lower() in ("get", "post", "put", "delete", "patch", "head"):
                    summary = (meta or {}).get("summary", "") if isinstance(meta, dict) else ""
                    ops.append({"method": m.upper(), "path": path, "summary": summary})
        print(f"  [+] {len(ops)} documented operations:")
        for o in ops:
            print(f"       {o['method']:<6} {o['path']:<34} {o['summary']}")
    else:
        print("  [-] No machine-readable spec found. Falling back to probe + built-in map.")

    results["spec"] = {"found": bool(ops), "operations": ops}
    return ops

# ---------------------------------------------------------------------------
# Pass 2 — blind path probe
# ---------------------------------------------------------------------------

def probe_paths(session, base, results, paths):
    print("\n=== [2] Common-path probe ===")
    found = []
    for p in paths:
        r = req(session, "GET", urljoin(base, p))
        if r is None:
            continue
        # Report anything that isn't a plain 404.
        if r.status_code != 404:
            line("GET", p, r)
            found.append({"path": p, "status": r.status_code, "shape": shape(r)})
    print(f"  [+] {len(found)} interesting paths (non-404).")
    results["probe"] = found
    return found

# ---------------------------------------------------------------------------
# Pass 3 — live calls (register, login, exercise every endpoint)
# ---------------------------------------------------------------------------

def live(session, base, results, token=None, username=None, password=None,
         reset_db=False):
    print("\n=== [3] Live endpoint exercise ===")
    username = username or f"disco_{rand()}"
    password = password or "Passw0rd!" + rand(4)
    email = f"{username}@example.com"

    # Reset the demo DB FIRST, before we register — otherwise it would wipe the
    # user we're about to create. Destructive, so it's opt-in via --reset-db.
    if reset_db:
        db = req(session, "GET", urljoin(base, "/createdb"))
        if db is not None:
            line("GET", "/createdb", db, note="recreate the demo database")
            results["createdb"] = {"status": db.status_code, "shape": shape(db)}

    if not token:
        # Register
        reg = req(session, "POST", urljoin(base, "/users/v1/register"), json={
            "username": username, "password": password, "email": email,
        })
        if reg is not None:
            line("POST", "/users/v1/register", reg)
        # Login
        log = req(session, "POST", urljoin(base, "/users/v1/login"), json={
            "username": username, "password": password,
        })
        if log is not None:
            line("POST", "/users/v1/login", log)
            try:
                token = (log.json() or {}).get("auth_token")
            except ValueError:
                token = None

    if token:
        print(f"  [+] auth token acquired ({token[:12]}...)")
        session.headers["Authorization"] = f"Bearer {token}"
    else:
        print("  [-] No token — auth-required endpoints will likely 401/403.")

    sample = {"username": username, "title": f"book_{rand(5)}"}
    called = []

    for method, path_tmpl, desc, needs_auth in VAMPI_ENDPOINTS:
        path = path_tmpl.format(**sample)
        body = None
        if path_tmpl == "/users/v1/{username}/email":
            body = {"email": f"{rand()}@example.com"}
        elif path_tmpl == "/users/v1/{username}/password":
            body = {"password": "N3w" + rand(6)}
        elif path_tmpl == "/books/v1" and method == "POST":
            body = {"book_title": sample["title"], "secret": "topsecret_" + rand()}

        r = req(session, method, urljoin(base, path), json=body)
        if r is None:
            continue
        line(method, path, r, note=desc)
        called.append({
            "method": method, "path": path, "desc": desc,
            "status": r.status_code, "shape": shape(r), "needs_auth": needs_auth,
        })

    results["live"] = {"username": username, "token": token, "calls": called}
    return called

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global TIMEOUT
    ap = argparse.ArgumentParser(description="VAMPI API discovery")
    ap.add_argument("-c", "--config", default=DEFAULT_CONFIG,
                    help="path to JSON config file (default %(default)s)")
    ap.add_argument("-u", "--url", help="base URL; overrides base_url from the config file")
    ap.add_argument("--token", help="reuse an existing auth token instead of registering")
    ap.add_argument("--username", help="username for the live pass")
    ap.add_argument("--password", help="password for the live pass")
    ap.add_argument("--no-live", action="store_true", help="skip the live/write pass")
    ap.add_argument("--reset-db", action="store_true",
                    help="hit /createdb to reseed the demo DB before the live pass "
                         "(destructive; runs before registration)")
    ap.add_argument("--json", metavar="FILE", help="write full results to a JSON file")
    args = ap.parse_args()

    cfg = load_config(args.config)
    TIMEOUT = cfg["timeout"]

    # CLI --url wins; otherwise use base_url from the config file.
    base = (args.url or cfg["base_url"]).rstrip("/") + "/"
    print(f"VAMPI discovery -> {base}")
    print("Reminder: only run against a target you are authorised to test.")

    session = requests.Session()
    session.headers["User-Agent"] = "vampi-discovery/1.0"
    results = {"base": base}

    # Quick reachability check.
    root = req(session, "GET", base)
    if root is None:
        sys.exit("Target unreachable. Check base_url in the config, or pass -u http://host:port")
    print(f"  [+] reachable — root returned {root.status_code}")

    discover_spec(session, base, results, cfg["spec_paths"])
    probe_paths(session, base, results, cfg["probe_paths"])
    if not args.no_live:
        live(session, base, results,
             token=args.token, username=args.username, password=args.password,
             reset_db=args.reset_db)
    else:
        print("\n=== [3] Live endpoint exercise === (skipped: --no-live)")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Full results written to {args.json}")

    print("\nDone.")


if __name__ == "__main__":
    main()
