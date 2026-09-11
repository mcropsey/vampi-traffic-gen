# VAMPI — Vuln / Challenge Scripts

Detection-pattern scripts for a VAMPI (Vulnerable API) lab instance. Each
script exercises ONE attack pattern (BOLA, mass assignment, SQLi, JWT forgery,
etc.) so an API-security sensor can be validated against it.

> **Scope:** VAMPI is a deliberately vulnerable training app. Point
> `vampi_config.yaml -> target.base_url` at **your own lab only** — never at a
> system you don't own. The live lab used here is
> `https://vampi.cropseyit.com`.

## Scripts

| Script | Pattern | Endpoint(s) |
|--------|---------|-------------|
| `vampi_challenge_01_excessive_data_exposure.py` | Sensitive data exposure (plaintext passwords) | `GET /users/v1/_debug` |
| `vampi_challenge_02_bola_users.py` | Broken Object Level Access (users) | `GET /users/v1/{username}` |
| `vampi_challenge_03_bola_books.py` | Broken Object Level Access (book secrets) | `GET /books/v1/{book_title}` |
| `vampi_challenge_04_mass_assignment_admin.py` | Mass assignment (register role) | `POST /users/v1/register`, `GET /me` |
| `vampi_challenge_05_unauthorized_password_change.py` | BOLA (cross-user password change) | `PUT /users/v1/{username}/password` |
| `vampi_challenge_06_sql_injection.py` | SQL injection | `GET /users/v1/{username}` |
| `vampi_challenge_07_user_enumeration.py` | User / credential enumeration | `POST /users/v1/login` |
| `vampi_challenge_08_unauthenticated_access.py` | Broken access control (no auth) | `/me`, `/users/v1/{u}`, `/books/v1/{t}`, `PUT .../password`, `DELETE ...` |
| `vampi_challenge_09_jwt_manipulation.py` | JWT alg=none / expired / long-life / garbage | `GET /me`, `GET /users/v1/{u}` |
| `vampi_challenge_10_privilege_escalation_delete.py` | Mass assignment + broken access control (delete) | `DELETE /users/v1/{username}` |

## Run

```bash
# from the vampi-traffic-gen/ directory
python3 vuln/vampi_challenge_01_excessive_data_exposure.py
python3 vuln/vampi_challenge_02_bola_users.py
# ...
python3 vuln/vampi_challenge_10_privilege_escalation_delete.py
```

Each reads `vampi_config.yaml` (falling back to the repo-root one) and prints
the HTTP status + whether the pattern appears to have succeeded. Exit code is
0 even when a pattern "succeeds" — these are diagnostic, not assertions.

## Notes

- The scripts only **demonstrate** the pattern; they don't attempt to fully
  exploit beyond the single probe shown.
- `vampi_challenge_01`, `_03`, `_06` deliberately do **not** print secret
  values (passwords / book secrets) — they only flag presence and count rows.
- `vampi_challenge_05` and `_10` use **throwaway** victim / attacker accounts
  so re-running never locks out or deletes the seeded lab users
  (`name1`/`pass1`, `name2`/`pass2`, `admin`/`pass1`).
- On this instance the protected endpoints (`/me`, book reads, cross-user
  password/email changes, `DELETE` as non-admin) correctly return `401` — the
  scripts report that honestly rather than forcing a "finding".
