#!/bin/bash
# Launch Chrome with remote debugging and network logging for LINE extension analysis.
#
# Usage:
#   ./scripts/line-chrome-capture.sh [output_dir]
#
# This starts Chrome with:
#   - Remote debugging on port 9222 (for CDP-based tools)
#   - Net-log capture to a JSON file (for offline analysis)
#   - Your default Chrome profile (so the LINE extension is already installed)
#
# When done, close Chrome. The net-log file will be at:
#   <output_dir>/line-net-log.json  (default: /tmp/line-capture/)

set -euo pipefail

OUTPUT_DIR="${1:-/tmp/line-capture}"
mkdir -p "$OUTPUT_DIR"
NETLOG_FILE="$OUTPUT_DIR/line-net-log.json"

CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [ ! -x "$CHROME" ]; then
    echo "Chrome not found at $CHROME"
    echo "Set CHROME env var to your Chrome binary path."
    exit 1
fi

echo "==> Starting Chrome with network capture"
echo "    Net-log: $NETLOG_FILE"
echo "    CDP:     http://localhost:9222"
echo ""
echo "    1. Open the LINE Chrome Extension and do your flow"
echo "    2. When done, close Chrome (Cmd+Q)"
echo "    3. Run:  /line-analyze $NETLOG_FILE"
echo ""

"$CHROME" \
    --remote-debugging-port=9222 \
    --log-net-log="$NETLOG_FILE" \
    --net-log-capture-mode=IncludeSensitive \
    2>/dev/null

echo ""
echo "==> Chrome closed. Net-log saved to: $NETLOG_FILE"
echo "    Size: $(du -h "$NETLOG_FILE" | cut -f1)"
