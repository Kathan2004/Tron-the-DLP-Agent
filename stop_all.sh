#!/bin/bash
# TRON THE DLP AGENT — Stop All Components
echo "Stopping TRON THE DLP AGENT..."

for component in server endpoint network web; do
    PID_FILE="/tmp/tron_logs/${component}.pid"
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null
            echo "  Stopped $component (PID: $PID)"
        else
            echo "  $component already stopped"
        fi
        rm -f "$PID_FILE"
    fi
done

# Also kill by port
lsof -ti :5001 | xargs kill -9 2>/dev/null

echo "All components stopped"
echo ""
echo "Logs are still at /tmp/tron_logs/"
