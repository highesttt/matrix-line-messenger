Parse and analyze a LINE Chrome Extension network capture.

## Arguments

$ARGUMENTS is the path to a net-log JSON file (default: `/tmp/line-capture/line-net-log.json`).

## What to do

1. Run the parser:
   ```
   python3 scripts/parse-line-traffic.py <net-log-file>
   ```
   This extracts LINE-related HTTP requests from the Chrome net-log and writes a `-parsed.json` file.

2. Read the parsed output JSON file.

3. Analyze the traffic and present findings organized by category:

   - **Thrift RPC** (`/api/talk/thrift/`): The main LINE API. Requests use LINE's Thrift-over-HTTP protocol. The `x-lhm` header indicates the Thrift method name. Compare against methods in `pkg/line/methods.go`.

   - **Long-poll / SSE** (`/api/talk/long-polling/`, `/api/operation/receive`): Real-time event delivery. LF1 is used during login verification, JQ for login polling, and SSE for ongoing message/operation streaming. Compare against `pkg/line/sse.go` and `pkg/line/client.go`.

   - **Auth** (`/api/auth/`): Token refresh and login flows. Compare against login methods in `pkg/line/client.go` (loginV2, confirmE2EELogin, tokenRefresh).

   - **Media/OBS** (`obs.line-apps.com`): Media upload/download. Check `x-obs-params` header for operation details, `x-obs-oid` in responses. Compare against `pkg/line/client.go` (UploadOBS, DownloadOBS).

   - **Stickers/CDN** (`stickershop`, `scdn`): Sticker image downloads.

   - **Secondary API** (`legy-jp.line-apps.com`): Link previews and page info. Compare against `pkg/line/client.go` (GetPageInfo).

4. For each interesting request, explain:
   - What the bridge equivalent is (or note if it's not implemented yet)
   - The request/response structure
   - Any headers that carry protocol-specific meaning

5. Highlight any **unimplemented** endpoints or behaviors that differ from what the bridge currently does. Cross-reference with `pkg/line/methods.go` and `pkg/connector/`.

## LINE protocol context

- The bridge identifies as LINE Chrome Extension: header `x-line-application` contains the app version string.
- Thrift RPC uses HTTP POST to `line-chrome-gw.line-apps.com/api/talk/thrift/Talk/<Service>/<Method>`.
- Auth token is in `x-line-access` header.
- E2EE messages have `chunks` field containing encrypted content (base64 segments).
- Operations have numeric `type` codes — see `pkg/connector/sync.go` and `pkg/connector/handle_message.go` for the operation type switch.
- Body content in the parsed output may be base64-encoded binary (Thrift serialization). Note the method name from headers rather than trying to decode the binary body.
