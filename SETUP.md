# VAMPI Discovery — Setup

Setup guide for running `vampi_discovery.py` against a local [VAMPI](https://github.com/erev0s/VAMPI) instance.

> **Authorised use only.** VAMPI is an intentionally vulnerable API built for
> learning. Only run this script against a VAMPI instance you own or have
> explicit permission to test.

---

## 1. Prerequisites

- Python 3.8+
- `pip`
- Docker (easiest way to run VAMPI) — or Python if you run VAMPI from source
- Network access to the target host/port

Check your Python:

```bash
python3 --version
```

---

## 2. Start VAMPI (the target)

Pick one.

### Option A — Docker (recommended)

```bash
docker run -p 5000:5000 erev0s/vampi:latest
```

VAMPI is now at `http://localhost:5000`.

### Option B — Docker Compose (from the repo)

```bash
git clone https://github.com/erev0s/VAMPI.git
cd VAMPI
docker compose up -d
```

### Option C — From source

```bash
git clone https://github.com/erev0s/VAMPI.git
cd VAMPI
pip install -r requirements.txt
python3 app.py
```

### Verify it's up

```bash
curl http://localhost:5000/
```

You should get a JSON banner telling you whether VAMPI is in **vulnerable** or
**secure** mode. To reset/seed the demo database:

```bash
curl http://localhost:5000/createdb
```

> **Vulnerable vs. secure mode:** VAMPI can run either way (set via the
> `vulnerable` flag / env). Run it in vulnerable mode if you want the discovery
> script's auth-required and BOLA-prone endpoints to actually return data.

---

## 3. Install the script's dependencies

Always use a virtual environment — it keeps `requests` out of your system Python.

```bash
python3 -m venv .venv        # create the venv (once)
source .venv/bin/activate    # activate it (.venv\Scripts\activate on Windows)
pip install -r requirements.txt
```

You'll know it's active when your prompt shows `(.venv)`. Re-run the `activate`
line in any new terminal before running the script. To leave the venv later:

```bash
deactivate
```

---

## 4. Run the discovery script

Make sure the venv is active first (`source .venv/bin/activate` — your prompt
should show `(.venv)`). Default target is `http://localhost:5000`:

```bash
python3 vampi_discovery.py
```

Against a different host and saving full results to JSON:

```bash
python3 vampi_discovery.py -u http://TARGET:5000 --json results.json
```

### What the three passes do

| Pass | Name | Action |
|------|------|--------|
| 1 | **Spec** | Fetches OpenAPI/Swagger from ~12 common locations, lists every documented method + path + summary. |
| 2 | **Probe** | Blind-checks a VAMPI-flavoured path wordlist, reports anything that isn't a plain 404. |
| 3 | **Live** | Registers a throwaway user, logs in, grabs the token, then calls every VAMPI endpoint and logs status + response shape. |

---

## 5. Common options

| Flag | Purpose |
|------|---------|
| `-u`, `--url` | Base URL of the target (default `http://localhost:5000`). |
| `--token` | Reuse an existing auth token instead of registering a new user. |
| `--username` / `--password` | Credentials for the live pass. |
| `--no-live` | Read-only: run spec + probe only, no registrations or writes. |
| `--json FILE` | Write the full structured results to a JSON file. |

### Examples

Read-only recon (no writes to the target):

```bash
python3 vampi_discovery.py --no-live
```

Reuse a token you already have:

```bash
python3 vampi_discovery.py --token eyJ0eXAiOiJKV1QiLCJhbGci...
```

---

## 6. Reading the output

Each line is `STATUS  METHOD  PATH  RESPONSE-SHAPE`, for example:

```
   200  GET    /users/v1                          json{users}
   200  GET    /users/v1/_debug                   json[3]{username,password,email}
   401  GET    /books/v1                          json{status,message}
```

- `json{...}` = object with those top-level keys
- `json[N]{...}` = array of N items with those keys
- `text:123b` = non-JSON body, 123 bytes

`/users/v1/_debug` returning passwords and a `401` flipping to `200` on other
users' data are the kinds of findings VAMPI is designed to surface.

---

## 7. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Target unreachable` | VAMPI isn't running or wrong port — confirm with `curl http://localhost:5000/`. |
| `Missing dependency` | venv isn't active or deps not installed — `source .venv/bin/activate` then `pip install -r requirements.txt`. |
| Everything returns `401/403` | Target is likely in secure mode or token wasn't acquired — check the login response, or pass `--token`. |
| Empty user/book lists | Seed the DB: `curl http://localhost:5000/createdb`. |
| `pip` refuses to install | Use a virtual env or `--break-system-packages` (see step 3). |

---

## 8. Reset between runs

The script registers throwaway users. To wipe state back to the seed data:

```bash
curl http://localhost:5000/createdb
```
