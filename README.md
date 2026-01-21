# matrix-line-messenger

[![Go Report Card](https://goreportcard.com/badge/github.com/highesttt/matrix-line-messenger)](https://goreportcard.com/report/github.com/highesttt/matrix-line-messenger)
![Languages](https://img.shields.io/github/languages/top/highesttt/matrix-line-messenger.svg)
[![License](https://img.shields.io/github/license/highesttt/matrix-line-messenger.svg)](LICENSE)

A Matrix bridge for LINE Messenger using mautrix-go.\
Based on the [mautrix-twilio](https://github.com/mautrix/twilio) bridge

## Known issues

> [!NOTE]
> Messages sent to the LINE Bot using Beeper Desktop may appear as indefinitely sending.\
> Use Beeper Mobile to send commands to the LINE Bot account after creating the chat with Beeper Desktop.

## Features

- [x] Basic messaging (encrypted text messages)
- [x] Actual login via mail/password (instead of access token)
- [x] Get own profile details (ID & Name)
- [x] Decrypt messages
- [x] Decrypt usernames
- [x] Sending messages
- [x] Read receipts
- [x] Reaction support (Receive ONLY)
- [x] Reply support
- [x] Prefetch chats
- [x] Group chats
- [x] Media messages (images, videos, voice notes, files)
- [x] Sticker support
- [x] Link previews
- [x] Message unsending/deletion\*
- [x] Leaving chats

\* If the other user unsends a message via LINE Mobile, it will not have any effects on Beeper.

## How to Use

1. Clone the repository:

    ```bash
    git clone https://github.com/highesttt/matrix-line-messenger.git
    cd matrix-line-messenger
    ```

2. Create a `data` directory for configuration and data storage:

    ```bash
    mkdir data
    ```

3. Create a configuration file using [bbctl](https://github.com/beeper/bridge-manager):

    ```bash
    bbctl c --type bridgev2 sh-line > config.yaml
    ```

4. Move the generated `config.yaml` into the `data` directory:

    ```bash
    mv config.yaml data/
    ```

5. Build and run the bridge using Docker (use -d for detached mode):

    ```bash
    docker compose up --build -d
    ```

    To run the bridge without rebuilding, use:

    ```bash
    docker compose up -d
    ```

## Login

### Using the LINE SelfHosted Bridge Bot

1. Open the Matrix client of your choice and start a chat with `@sh-linebot:your.matrix.homeserver.domain`. (For local beeper bridges, use `@sh-linebot:beeper.local`)
2. Send the command `login` and follow the instructions to log in to your LINE account.

or

### Via Beeper Desktop Settings

1. Open Beeper Desktop Settings
2. Navigate to `Bridges`
3. Click on the three dots next to your LINE Bridge and select `Experimental: Add an account`
4. Follow the instructions to log in to your LINE account.

## Can't log in?

This bridge uses the email from your Account information. If your account is an older account, you signed in using phone number or signed in with Google, you will not have an email set for your LINE account.

### How to set an email for your LINE account

1. Open the LINE app on your mobile device.
2. Go to `Settings` > `Account`.
3. Tap on `Email address` and set your email address.
