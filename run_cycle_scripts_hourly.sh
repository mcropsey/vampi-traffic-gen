#!/bin/bash
# Run all VAMPI cycle scripts once per hour at the bottom of the hour.
# Logs to /var/log/vampi_cycle.log

LOG_FILE="/var/log/vampi_cycle.log"
CYCLE_DIR="/home/mcropsey/vampi-traffic-gen"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Prefer the repo venv if present, else system python3.
if [ -f "$CYCLE_DIR/.venv/bin/python3" ]; then
    PYTHON="$CYCLE_DIR/.venv/bin/python3"
else
    PYTHON="python3"
fi

{
    echo "[$TIMESTAMP] Starting VAMPI cycle scripts traffic generation..."
    cd "$CYCLE_DIR" || exit 1

    CYCLE_SCRIPTS=(
        "vampi_users_cycle.py"
        "vampi_books_cycle.py"
    )

    for script in "${CYCLE_SCRIPTS[@]}"; do
        if [ ! -f "$script" ]; then
            echo "[$TIMESTAMP] $script: NOT FOUND"
            continue
        fi

        if timeout 60 "$PYTHON" "$script" > /dev/null 2>&1; then
            echo "[$TIMESTAMP] $script: SUCCESS"
        else
            echo "[$TIMESTAMP] $script: FAILED/TIMEOUT"
        fi
    done

    echo "[$TIMESTAMP] Cycle scripts run complete"
} >> "$LOG_FILE" 2>&1
