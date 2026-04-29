# Letter Sealing

This note summarizes what issue [#42](https://github.com/highesttt/matrix-line-messenger/issues/42) and issue [#54](https://github.com/highesttt/matrix-line-messenger/issues/54) currently tell us about Letter Sealing support in this bridge, and how that lines up with the current implementation.

## TL;DR

- The bridge supports both `LSON` and `LSOFF` accounts for login and messaging.
- Text messages work in all combinations: `LSON`/`LSOFF` direct messages, mixed groups, and business/bot accounts.
- Image, video, file, and audio sending works for all user types. E2EE media uses encrypted OBS upload; plain media uses the `r/talk/m` post-send upload path.
- Transparent PNGs are composited onto a white background before upload, matching LINE native client behavior.

## Terms

- `LSON`: LINE user with Letter Sealing enabled.
- `LSOFF`: LINE user with Letter Sealing disabled.

## Current behavior matrix

| Scenario | Current status | Notes |
| --- | --- | --- |
| Bridge account is `LSOFF` and tries to log in | `WORKS` | Uses non-E2EE login flow: fresh RSA key, type 0 retry, JQ polling. |
| Bridge account is `LSON` and tries to log in | `WORKS` | Uses E2EE login flow: LF1 polling, ConfirmE2EELogin, key chain export. |
| Bridge account is `LSON`, receives direct message from `LSOFF` | `WORKS` | Confirmed in issue testing. |
| Bridge account is `LSON`, receives group message in a chat that includes `LSOFF` | `WORKS` | Confirmed in issue testing. |
| Bridge account is `LSON`, sends direct message to `LSOFF` | `WORKS` | Detects missing peer E2EE key and falls back to plain text send. |
| Bridge account is `LSON`, sends group message to a room that includes `LSOFF` | `WORKS` | Detects missing group shared key and falls back to plain text send. |
| Bridge account is `LSON`, sends to `LSON` only chats | `WORKS` | Uses full E2EE encryption path. |
| Bridge account is `LSOFF`, sends direct message to `LSON` | `WORKS` | Sends as plain text (E2EE not initialized). |
| Bridge account is `LSOFF`, sends to mixed groups | `WORKS` | Sends as plain text. |
| Bridge account is `LSOFF`, sends to bot/business account | `WORKS` | Sends as plain text. |
| Bridge account sends images/media to `LSON` | `WORKS` | E2EE encrypted media with keyMaterial in payload. |
| Bridge account sends images/media to `LSOFF` or plain chats | `WORKS` | Plain media uploaded via `r/talk/m/{msgId}` after sending. |

## How it works

### Login paths

The bridge supports QR code login and email/password login.

**QR code login (primary):**
1. The bridge creates a QR login session and QR callback URL.
2. Before displaying the QR, it appends a Curve25519 public key as `secret` with `e2eeVersion=1`, matching the LINE Chrome Extension.
3. The user scans the QR code with LINE mobile.
4. If the stored LINE certificate is valid, the PIN step is skipped. Otherwise, the bridge displays a 6-digit PIN for the user to enter on mobile.
5. `qrCodeLoginV2` returns access tokens, a refreshed certificate, and E2EE keychain metadata.
6. The bridge unwraps the encrypted keychain with the matching QR login private key.

**Email/password login (secondary):**

This path is selected manually and then diverges based on whether the LINE account has Letter Sealing enabled:

**LSON accounts (E2EE login):**
1. `loginV2` with `type: 2` and E2EE `secret` returns a verifier and PIN.
2. Background goroutine polls `LF1` endpoint until the user confirms on their phone.
3. LF1 returns `EncryptedKeyChain` and `PublicKey`.
4. `confirmE2EELogin` completes the E2EE handshake.
5. `loginV2WithVerifier` finalizes and returns access tokens + E2EE key material.

**LSOFF accounts (non-E2EE login):**
1. `loginV2` with `type: 2` and E2EE `secret` fails with code 89 "not supported".
2. Bridge fetches a fresh RSA key (LINE invalidates the previous one after the failed attempt).
3. Retry `loginV2` with `type: 0`, no secret, and the new RSA key returns a verifier and PIN.
4. Background goroutine polls `JQ` endpoint (not LF1) until the user confirms on their phone.
5. JQ returns `authPhase: "QRCODE_VERIFIED"`.
6. `loginV2WithVerifier` finalizes and returns access tokens (no E2EE data).

### Send path

The bridge determines E2EE capability per-chat before sending:

- If `lc.E2EE == nil` (LSOFF bridge account): all messages sent as plain text.
- For 1:1 chats: `ensurePeerKey` probes the peer's E2EE public key. If the peer is `LSOFF`, falls back to plain text.
- For groups: `fetchAndUnwrapGroupKey` attempts to get the group shared key. If not available (mixed group), falls back to plain text.
- E2EE capability is cached per-peer and per-group with a 1-hour TTL.

**Plain text media** uses a different upload flow than E2EE media:
- E2EE: encrypt data, upload to `r/talk/emi/{id}` (OBS), send message with OID in metadata.
- Plain: send message first, then upload raw data to `r/talk/m/{serverMessageId}`.

### Receive path

- `pkg/connector/handle_message.go` lazily fetches peer keys or group keys based on key IDs in incoming message chunks.
- Incoming messages from `LSOFF` users arrive as plain text and are handled without decryption.

## Test matrix

### Login

| Test case | Status |
| --- | --- |
| `LSOFF` bridge account login | Verified |
| `LSON` bridge account login | Verified |

### Text messages

| Test case | Path | Status |
| --- | --- | --- |
| `LSON` bridge -> `LSON` peer (DM) | E2EE | Verified |
| `LSON` bridge -> `LSOFF` peer (DM) | Plain | Verified |
| `LSON` bridge -> `LSON`-only group | E2EE | Verified |
| `LSON` bridge -> mixed group | Plain | Verified |
| `LSON` bridge -> bot/business account | Plain | Verified |
| `LSOFF` bridge -> `LSON` peer (DM) | Plain | Verified |
| `LSOFF` bridge -> `LSOFF` peer (DM) | Plain | Not tested |
| `LSOFF` bridge -> mixed group (LSOFF created) | Plain | Verified |
| `LSOFF` bridge -> mixed group (LSON created) | Plain | Verified |
| `LSOFF` bridge -> bot/business account | Plain | Verified |

### Receiving messages

| Test case | Status |
| --- | --- |
| Incoming E2EE text from `LSON` peer | Verified |
| Incoming plain text from `LSOFF` peer | Verified |
| Incoming E2EE group message (`LSON`-only) | Verified |
| Incoming group message (mixed group) | Verified |

### Media (images)

| Test case | Path | Status |
| --- | --- | --- |
| Image to `LSON` peer | E2EE (`emi` upload) | Verified |
| Image to `LSOFF` peer | Plain (`m` upload) | Verified |
| Image to mixed group | Plain (`m` upload) | Verified |
| Image to bot/business account | Plain (`m` upload) | Verified |
| Transparent PNG | White background compositing | Verified |

### Media (audio, video, files)

| Test case | Path | Status |
| --- | --- | --- |
| Video to `LSON` peer | E2EE (`emv` upload) | Verified |
| Video to `LSOFF` / plain chats | Plain (`m` upload) | Verified |
| File to `LSON` peer | E2EE (`emf` upload) | Verified |
| File to `LSOFF` / plain chats | Plain (`m` upload) | Verified |
| Audio to `LSON` peer | E2EE (`ema` upload) | Verified |
| Audio to `LSOFF` / plain chats | Plain (`m` upload) | Verified |

### Media receive (incoming to Beeper)

| Test case | Path | Status |
| --- | --- | --- |
| Incoming image from plain chat | Plain (`m` download) | Verified |
| Incoming image from E2EE chat | E2EE (`emi` download) | Verified |
| Incoming video from plain chat | Plain (`m` download) | Not tested |
| Incoming video from E2EE chat | E2EE (`emv` download) | Not tested |
| Incoming file from plain chat | Plain (`m` download) | Not tested |
| Incoming file from E2EE chat | E2EE (`emf` download) | Not tested |
| Incoming audio from plain chat | Plain (`m` download) | Verified |
| Incoming audio from E2EE chat | E2EE (`ema` download) | Verified |

### Re-login and token refresh

| Test case | Status |
| --- | --- |
| `LSON` re-login after token expiry | Not tested |
| `LSOFF` re-login after token expiry | Not tested |

## References

- Issue [#42: login fails for accounts with letter sealing OFF](https://github.com/highesttt/matrix-line-messenger/issues/42)
- Issue [#54: failure to decrypt when sending message to user with letter sealing off](https://github.com/highesttt/matrix-line-messenger/issues/54)
- [About Letter Sealing | LINE Help Center](https://help.line.me/line/?contentId=50000087)
- [October, 2015 LINE Introduces Letter Sealing Feature for Advanced Security](https://www.linecorp.com/en/pr/news/en/2015/1107)
- [LINE Encryption Report (2024)](https://www.lycorp.co.jp/en/privacy-security/security/transparency/encryption-report/2024/)
