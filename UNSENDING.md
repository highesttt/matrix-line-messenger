# Message Unsending / Deletion

## How it works

The bridge supports unsending (deleting) messages in both directions:

- **Matrix -> LINE**: When you delete a message in your Matrix client (e.g. "Delete for Everyone" in Beeper), the bridge calls LINE's `unsendMessage` API.
- **LINE -> Matrix**: When someone unsends a message on LINE, the bridge receives the operation and redacts the message on the Matrix side.

## 24-hour limit (free accounts)

LINE imposes a **24-hour limit** on unsending messages for free accounts. If you try to unsend a message older than 24 hours, LINE rejects the request with:

```
TalkException code 71: "message too old"
messageUnsendPeriodMillis: 86400000 (24h)
```

The bridge advertises this limit via `DeleteMaxAge: 24h` in the room capabilities, so Matrix clients that support this field (like Beeper) should hide the "Delete for Everyone" option for messages older than 24 hours.

As a fallback, if a client ignores `DeleteMaxAge` and attempts the unsend anyway, the bridge returns a permanent failure with a notice: _"message too old to unsend on LINE (24h limit)"_.

## Paid accounts

LINE paid accounts may have the ability to unsend messages at any time. This is not yet specifically handled by the bridge -- the 24-hour limit is applied uniformly. If you have a paid account and need this, please open an issue.
