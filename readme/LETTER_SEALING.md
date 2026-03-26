# Letter Sealing

This note summarizes what issue [#42](https://github.com/highesttt/matrix-line-messenger/issues/42) and issue [#54](https://github.com/highesttt/matrix-line-messenger/issues/54) currently tell us about Letter Sealing support in this bridge, and how that lines up with the current implementation.

## TL;DR

- The bridge currently assumes the logged-in LINE account has Letter Sealing enabled.
- Logging in with a LINE account that has Letter Sealing disabled is currently unsupported.
- If the bridge account has Letter Sealing enabled, incoming messages from users who have it disabled appear to work.
- Sending from the bridge to a user with Letter Sealing disabled, or to a group that includes such a user, does not currently work.
- Based on the current logs and code paths, full support probably needs an alternate non-E2EE send path, not just better retries.

## Terms

- `LSON`: LINE user with Letter Sealing enabled.
- `LSOFF`: LINE user with Letter Sealing disabled.

## Current behavior matrix

| Scenario | Current status | Notes |
| --- | --- | --- |
| Bridge account is `LSOFF` and tries to log in | `FAIL` | PIN step is reached, but the login never completes successfully. |
| Bridge account is `LSON`, receives direct message from `LSOFF` | `WORKS` | Confirmed in issue testing. |
| Bridge account is `LSON`, receives group message in a chat that includes `LSOFF` | `WORKS` | Confirmed in issue testing. |
| Bridge account is `LSON`, sends direct message to `LSOFF` | `FAIL` | Direct send cannot obtain a usable peer E2EE key. |
| Bridge account is `LSON`, sends group message to a room that includes `LSOFF` | `FAIL` | Group send cannot obtain a group shared key. |
| Bridge account is `LSON`, sends to `LSON` only chats | `WORKS` | Works after normal login/re-login. |

## What the current code is assuming

### Login path

The login flow is built around LINE's E2EE login handshake:

- `pkg/line/client.go` waits for LF1 login polling data.
- If LF1 returns `EncryptedKeyChain` and `PublicKey`, the bridge calls `confirmE2EELogin` and then finalizes the login with `loginV2WithVerifier`.
- `pkg/connector/connector.go` then exports and stores the user's E2EE keys when that key chain is present.

Issue `#42` shows that accounts with Letter Sealing disabled can still receive the PIN prompt, but the bridge never reaches a successful final login. In practice, that means the bridge does not currently have a working non-Letter-Sealing login path.

### Direct message send path

Direct sends always go through E2EE:

- `pkg/connector/send_message.go` calls `ensurePeerKey(...)`.
- `pkg/connector/e2ee_keys.go` implements that by calling `negotiateE2EEPublicKey`.
- The result is passed into `EncryptMessageV2Raw(...)`.

In issue `#54`, the failing direct-chat case produced a parsed error like:

`missing fields (pub=false keyID=-1 raw={"allowedTypes":[],"specVersion":-1})`

That strongly suggests LINE is not returning a usable E2EE public key for `LSOFF` peers. This looks more like "there is no key to use here" than "the bridge forgot to retry".

### Group send path

Group sends also assume Letter Sealing is available for the chat:

- `pkg/connector/send_message.go` calls `fetchAndUnwrapGroupKey(...)` before encrypting.
- `pkg/connector/e2ee_keys.go` fetches either `getLastE2EEGroupSharedKey` or `getE2EEGroupSharedKey`.
- `pkg/e2ee/manager.go` then encrypts with `EncryptGroupMessageRaw(...)`.

In issue `#54`, the failing mixed-group case logged:

`TalkException code 5 reason "not found"`

followed by:

`encrypt failed: no group key found`

That means the bridge has no group key material to encrypt with when the chat is not fully Letter Sealed.

### Receive path

Receiving is in better shape than sending:

- `pkg/connector/handle_message.go` can lazily fetch peer keys or group keys based on the key IDs found in incoming message chunks.
- The bridge can sometimes decrypt incoming messages even when it cannot originate new ones for the same chat.

This matches the current field reports from the issues: inbound direct and group messages involving `LSOFF` users are readable, but outbound messages fail.

## Working conclusion

The bridge currently supports Letter Sealing well enough to:

- log in with `LSON` accounts,
- decrypt normal `LSON` traffic, and
- receive some traffic from chats that include `LSOFF` users.

It does not currently support using the bridge as a full sender in `LSOFF` scenarios.

The most likely explanation, based on the current code and logs, is:

- `LSOFF` accounts do not complete the same E2EE login handshake the bridge expects,
- direct chats with `LSOFF` users do not expose a usable E2EE public key through the current RPCs, and
- mixed groups do not expose a usable E2EE group shared key through the current RPCs.

That is an inference from the current issue reports and logs, but it fits the observed behavior cleanly.

## Recommended product stance right now

Until a verified alternate send/login path exists, the safest thing to document and enforce is:

1. The LINE account used to log into the bridge must have Letter Sealing enabled.
2. Chats involving `LSOFF` users should be treated as partially supported at best.
3. The bridge should fail fast with a clear, specific error instead of surfacing generic internal errors or repeatedly trying to recover the token.

## Checklist for proper support

### Immediate UX and guardrails

- [ ] Replace the generic login failure with a message that explicitly says Letter Sealing must be enabled on the LINE account used by the bridge.
- [ ] Document the setting path in user-facing docs: `LINE app -> Settings -> Privacy -> Letter Sealing`.
- [ ] Detect the known `LSOFF` login failure mode and stop the flow cleanly instead of leaving the bridge `UNCONFIGURED` with an internal error.
- [ ] Detect the known direct-send failure mode where `negotiateE2EEPublicKey` returns no usable key and return a specific unsupported-chat error.
- [ ] Detect the known group-send failure mode where `getLastE2EEGroupSharedKey` returns `not found` and return a specific unsupported-chat error.
- [ ] Avoid automatic token refresh/re-login loops when the real problem is missing Letter Sealing material rather than expired credentials.

### Protocol investigation

- [ ] Capture raw LF1/login responses for a bridge account with Letter Sealing disabled.
- [ ] Capture raw `negotiateE2EEPublicKey` and `getE2EEPublicKey` responses for a direct chat with an `LSOFF` user.
- [ ] Capture raw `getLastE2EEGroupSharedKey` / `getE2EEGroupSharedKey` responses for a mixed `LSON` + `LSOFF` group.
- [ ] Compare the bridge RPCs with traffic from the official LINE clients for the same chats.
- [ ] Determine whether official clients fall back to plaintext, legacy crypto, or a different RPC entirely when a chat is not fully Letter Sealed.
- [ ] Confirm whether there is a reliable API surface for detecting chat-level or peer-level Letter Sealing capability before send time.

### Implementation work

- [ ] Add a dedicated non-E2EE or alternate send path for direct chats when the peer has no usable E2EE key.
- [ ] Add a dedicated non-group-key or alternate send path for groups that are not fully Letter Sealed.
- [ ] Route outgoing sends based on chat capability instead of assuming E2EE for every direct and group chat.
- [ ] Persist any capability detection needed so the bridge does not rediscover the same unsupported state on every send.
- [ ] Keep the current E2EE path as the fast path for `LSON` to `LSON` traffic.

### Test matrix

- [ ] `LSOFF` bridge account login.
- [ ] `LSON` bridge account login.
- [ ] `LSON` -> `LSOFF` direct send from Beeper.
- [ ] `LSOFF` -> `LSON` direct receive into Beeper.
- [ ] `LSON` -> mixed group send from Beeper.
- [ ] Mixed group receive into Beeper.
- [ ] `LSON` -> `LSON` direct and group regression tests.
- [ ] Chat created before enabling Letter Sealing, then re-tested after enabling it for all members.
- [ ] Chats created by iOS and Android clients.
- [ ] Business chats, if the API surface differs there.

## References

- Issue [#42: login fails for accounts with letter sealing OFF](https://github.com/highesttt/matrix-line-messenger/issues/42)
- Issue [#54: failure to decrypt when sending message to user with letter sealing off](https://github.com/highesttt/matrix-line-messenger/issues/54)
- [About Letter Sealing | LINE Help Center](https://help.line.me/line/?contentId=50000087)
- [October, 2015 LINE Introduces Letter Sealing Feature for Advanced Security](https://www.linecorp.com/en/pr/news/en/2015/1107)
- [LINE Encryption Report (2024)](https://www.lycorp.co.jp/en/privacy-security/security/transparency/encryption-report/2024/)
