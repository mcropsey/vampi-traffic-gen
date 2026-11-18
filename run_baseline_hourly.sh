#!/bin/bash
# Run all VAMPI baseline scripts once per hour.
# Logs to /home/mcropsey/vampi-traffic-gen/logs/vampi_baseline.log

LOG_FILE="/home/mcropsey/vampi-traffic-gen/logs/vampi_baseline.log"
BASELINE_DIR="/home/mcropsey/vampi-traffic-gen/baseline"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Prefer the repo venv if present, else system python3.
if [ -f "/home/mcropsey/vampi-traffic-gen/.venv/bin/python3" ]; then
    PYTHON="/home/mcropsey/vampi-traffic-gen/.venv/bin/python3"
else
    PYTHON="python3"
fi

{
    echo "[$TIMESTAMP] Starting VAMPI baseline training data generation..."
    cd "$BASELINE_DIR" || exit 1

    for i in {01..10}; do
        SCRIPT=$(ls baseline_${i}_*.py 2>/dev/null)
        if [ -z "$SCRIPT" ]; then
            echo "[$TIMESTAMP] Baseline $i: Script not found"
            continue
        fi

        if timeout 20 "$PYTHON" "$SCRIPT" > /dev/null 2>&1; then
            echo "[$TIMESTAMP] Baseline $i: SUCCESS"
        else
            echo "[$TIMESTAMP] Baseline $i: FAILED/TIMEOUT"
        fi
    done

    echo "[$TIMESTAMP] Baseline training run complete"
} >> "$LOG_FILE" 2>&1
