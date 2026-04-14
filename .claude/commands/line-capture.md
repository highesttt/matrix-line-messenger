Launch Chrome with network capture enabled for LINE Chrome Extension analysis.

## What to do

1. **Close any running Chrome instances first** (Chrome only supports one instance per profile with remote debugging). Warn the user if Chrome is running.

2. Run the capture script:
   ```
   bash scripts/line-chrome-capture.sh /tmp/line-capture
   ```
   This launches Chrome with:
   - Remote debugging on port 9222
   - Full network logging to `/tmp/line-capture/line-net-log.json`
   - The user's default Chrome profile (LINE extension should already be installed)

3. Tell the user:
   - Open the LINE Chrome Extension (browser toolbar icon)
   - Perform whatever flow they want to analyze
   - When done, quit Chrome completely (Cmd+Q)

4. Once Chrome is closed, the net-log file is ready. Tell the user to run `/line-analyze` next.
