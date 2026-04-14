#!/bin/bash
# Launch Chrome with CDP-based network capture for LINE extension analysis.
#
# Usage:
#   ./scripts/line-chrome-capture.sh [output_dir]
#
# This starts Chrome with remote debugging and runs a CDP listener that
# captures all LINE traffic including SSE EventSource message bodies.
#
# Uses a separate Chrome profile at <output_dir>/chrome-debug-profile.
# On first run, you'll need to install the LINE extension from the Chrome
# Web Store and log in. The profile persists across runs.
#
# When done, close Chrome (Cmd+Q). The capture files will be at:
#   <output_dir>/line-cdp-capture.json  — CDP capture (SSE + request bodies)
#   <output_dir>/line-net-log.json      — Chrome net-log (low-level backup)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-/tmp/line-capture}"
mkdir -p "$OUTPUT_DIR"
NETLOG_FILE="$OUTPUT_DIR/line-net-log.json"
CDP_FILE="$OUTPUT_DIR/line-cdp-capture.json"
DEBUG_PROFILE="$OUTPUT_DIR/chrome-debug-profile"

CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [ ! -x "$CHROME" ]; then
    echo "Chrome not found at $CHROME"
    echo "Set CHROME env var to your Chrome binary path."
    exit 1
fi

FIRST_RUN=false
if [ ! -d "$DEBUG_PROFILE" ]; then
    FIRST_RUN=true
    mkdir -p "$DEBUG_PROFILE"
fi

echo "==> Starting Chrome with CDP + net-log capture"
echo "    CDP output:  $CDP_FILE"
echo "    Net-log:     $NETLOG_FILE"
echo "    Profile:     $DEBUG_PROFILE"
echo ""
if [ "$FIRST_RUN" = true ]; then
    echo "    FIRST RUN: Install LINE extension from Chrome Web Store and log in."
    echo "    The profile persists — you only need to do this once."
    echo ""
fi
echo "    1. Open the LINE Chrome Extension and do your flow"
echo "    2. When done, close Chrome (Cmd+Q)"
echo ""

# Chrome 146+ requires --user-data-dir for remote debugging.
"$CHROME" \
    --remote-debugging-port=9222 \
    --remote-allow-origins="*" \
    --user-data-dir="$DEBUG_PROFILE" \
    --log-net-log="$NETLOG_FILE" \
    --net-log-capture-mode=IncludeSensitive \
    2>/dev/null &
CHROME_PID=$!

# Start the CDP capture (it waits for Chrome to be ready)
python3 "$SCRIPT_DIR/line-cdp-capture.py" "$CDP_FILE" &
CDP_PID=$!

# Wait for Chrome to exit
wait $CHROME_PID 2>/dev/null || true

# Give CDP listener a moment to finish saving
sleep 1

# Stop CDP capture if still running
if kill -0 $CDP_PID 2>/dev/null; then
    kill $CDP_PID 2>/dev/null
    wait $CDP_PID 2>/dev/null || true
fi

echo ""
echo "==> Chrome closed. Captures saved:"
[ -f "$CDP_FILE" ] && echo "    CDP:     $CDP_FILE ($(du -h "$CDP_FILE" | cut -f1))"
[ -f "$NETLOG_FILE" ] && echo "    Net-log: $NETLOG_FILE ($(du -h "$NETLOG_FILE" | cut -f1))"
