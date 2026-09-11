# VAMPI Lab Traffic Generator

Generates API traffic against a **VAMPI** (Vulnerable API) training instance to
(1) advance the API through your security sensor's *learning period* and
(2) exercise the specific detection patterns that show up as findings.

> VAMPI is a deliberately vulnerable API built for security training. Point this
> tool at **your own lab only** — never at systems you don't own. The live lab
> used here is `https://vampi.cropseyit.com`.

## Files

| File | Purpose |
|------|---------|
| `vampi_traffic.py` | The main traffic generator (warmup + findings). |
| `vampi_common.py` | Shared helpers (config, login, consumers, JWT forging, stats, 60 s token refresh). |
| `vampi_config.yaml` | All options live here — edit this, not the scripts. |
| `vampi_users_cycle.py` | Normal account-cycle traffic (register, login, read/update user). |
| `vampi_books_cycle.py` | Normal book-cycle traffic (list, add, read book + secret). |
| `baseline/` | 10 "normal" training scripts (one behavior each). |
| `vuln/` | 10 detection-pattern scripts (BOLA, mass assignment, SQLi, JWT…). |
| `run_cycle_scripts_hourly.sh` | Hourly runner for the cycle scripts. |
| `run_baseline_hourly.sh` | Hourly runner for the baseline scripts. |
| `requirements.txt` | Python dependencies. |
| `vampi_openapi3.yml` | The VAMPI API spec (reference for endpoints). |
| `README.md` | This file. |

## Prerequisites

- Python 3.8 or newer (`python3 --version` to check).
- Network access from your machine to the VAMPI instance.

## Setup (virtual environment)

Working in a virtual environment keeps these dependencies isolated from your
system Python. From the project folder:

```bash
# 1. create the venv
python3 -m venv .venv

# 2. activate it
source .venv/bin/activate

# 3. install dependencies into the venv
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Once activated, your prompt shows `(.venv)`. To leave it later, run
`deactivate`.

## Configure

Open `vampi_config.yaml` and set the things specific to your lab:

```yaml
target:
  base_url: "https://vampi.cropseyit.com"   # <- your VAMPI instance

known_users:
  users:
    - username: name1
      password: pass1
      email: mail1@mail.com
    - username: name2
      password: pass2
      email: mail2@mail.com
    - username: admin
      password: pass1
      email: admin@mail.com
```

Every script reads these same values, so set them once. Every option in the
file has an inline comment explaining exactly what changes when you edit it
(which phases run, consumer volume, credential-attempt volume, timeouts, etc.).
Review them before your first run.

## Run

### Main generator (warmup + findings)

```bash
python3 vampi_traffic.py
```

That reads `vampi_config.yaml` from the current folder. To use a different
config file:

```bash
python3 vampi_traffic.py --config staging.yaml
```

Driven by the `run:` switches in the config:

- **warmup** — many distinct-consumer journeys (register → login → browse) to
  build the observed-consumer count and move the API out of learning.
- **findings** — labeled populations: *authenticated* (valid sessions),
  *unauthenticated* (no token), and *bad-token* (unsigned / expired /
  long-life / garbage tokens).

A typical first-day pattern is warmup-only (`run.findings: false`) to start
the learning clock, then flip to `run.findings: true` once the API reports out
of learning so the detection patterns actually surface.

### Cycle scripts (normal traffic, per area)

```bash
python3 vampi_users_cycle.py
python3 vampi_books_cycle.py
```

### Baseline scripts (normal behavior, one each)

```bash
# from the vampi-traffic-gen/ directory
python3 baseline/baseline_01_home_banner.py
# ...
python3 baseline/baseline_10_update_own_email.py
```

### Vuln / challenge scripts (detection patterns)

```bash
# from the vampi-traffic-gen/ directory
python3 vuln/vampi_challenge_01_excessive_data_exposure.py
# ...
python3 vuln/vampi_challenge_10_privilege_escalation_delete.py
```

See `vuln/INDEX.md` for the full list and what each one exercises.

## Hourly runners

```bash
# install both (adjust the minute if you don't want the bottom-of-the-hour)
( crontab -l 2>/dev/null; echo "0 * * * * /home/mcropsey/vampi-traffic-gen/run_cycle_scripts_hourly.sh" ) | crontab -
( crontab -l 2>/dev/null; echo "0 * * * * /home/mcropsey/vampi-traffic-gen/run_baseline_hourly.sh" ) | crontab -
```

- `run_cycle_scripts_hourly.sh` → logs to `/var/log/vampi_cycle.log`
- `run_baseline_hourly.sh` → logs to `/var/log/vampi_baseline.log`

Both prefer the repo `.venv` if it exists, else fall back to system `python3`.

## Troubleshooting

- **`Missing dependency. Run: pip install pyyaml`** — the venv isn't active or
  deps aren't installed. Re-activate and run the `pip install -r requirements.txt`
  step. Confirm with `python3 -m pip list | grep -i pyyaml`.
- **`obtained tokens for 0/3 known users`** — the `known_users` list doesn't
  match the lab accounts. Fix them and re-run.
- **`NotOpenSSLWarning ... LibreSSL`** (yellow line on macOS) — harmless.
  Silence it by uncommenting `urllib3<2` in `requirements.txt` and reinstalling.
- **Connection errors / timeouts** — confirm `target.base_url` is reachable
  (`curl https://vampi.cropseyit.com/`) and raise `http.timeout` if the lab is
  slow.

## Notes

- **Short-lived tokens.** VAMPI issues JWTs that expire in ~60 s on this
  instance. `vampi_common.py` re-logs in on demand and retries once on a `401`,
  so you don't manage token refresh yourself.
- Status codes printed in the run summary are VAMPI's responses, **not** the
  sensor's verdict. Findings are raised by the monitoring platform after the
  learning period completes.
- Re-running is safe; warmup and the vuln scripts only create fresh throwaway
  accounts / books and don't disturb the known lab users.
- `vuln/vampi_challenge_01`, `_03`, `_06` deliberately do not print secret
  values (passwords / book secrets) — they only flag presence and count rows.
- The protected endpoints (`/me`, book reads, cross-user password/email
  changes, `DELETE` as non-admin) correctly return `401` on this instance; the
  scripts report that honestly rather than forcing a "finding".
