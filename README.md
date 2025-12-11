# mautrix-line-messenger

[![Go Report Card](https://goreportcard.com/badge/github.com/highesttt/mautrix-line-messenger)](https://goreportcard.com/report/github.com/highesttt/mautrix-line-messenger)
![Languages](https://img.shields.io/github/languages/top/highesttt/mautrix-line-messenger.svg)
[![License](https://img.shields.io/github/license/highesttt/mautrix-line-messenger.svg)](LICENSE)

A Matrix bridge for LINE Messenger using mautrix-go.\
Based on the [mautrix-twilio](https://github.com/mautrix/twilio) bridge

## Roadmap

- [x] Basic messaging (encrypted text messages)
- [ ] Decrypt messages
- [ ] Decrypt usernames
- [ ] Sending messages
- [ ] Prefetch chats
- [ ] Get own profile details (ID & Name)
- [ ] Actual login via mail/password (instead of access token)
- [ ] Group chats
- [ ] Media messages (images, videos, voice notes, files)
- [ ] Sticker support

## How obtain LINE access token

Sign in via the [LINE Chrome extension](https://chromewebstore.google.com/detail/line/ophjlpahpchlmihnnnihgmmeilfjmjjc) and get the access token from your browser's developer tools / cookies.

1. Obtain a LINE access token via the LINE Chrome extension.
2. Set up a Matrix homeserver and a Beeper instance with the Bridge V2 enabled.
3. Add the mautrix-line-messenger bridge to Beeper and configure it with your LINE access token.
