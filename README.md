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
- [x] Message unsending/deletion
- [x] Leaving chats

## How to Use

1. Prerequisites:

    - For Windows users: Install MSYS2 and gcc for mingw-w64

    ```bash
    # Step 1: Make sure you have MSYS2 installed and gcc for mingw-w64
    winget install MSYS2.MSYS2
    # Open MSYS2 MinGW 64-bit terminal and install necessary packages
    pacman -Syu mingw-w64-x86_64-gcc cmake
    ```

    Ensure you have [Docker](https://www.docker.com/get-started/) and [Docker Compose](https://docs.docker.com/compose/install/) installed on your system. OR if you want to build and run without Docker, ensure you have Go installed along with necessary build tools (like the olm library and bbctl).

    - Compile bbctl from source if you don't have it already:

    ```bash
    git clone https://github.com/beeper/bridge-manager.git
    cd bridge-manager

    # For windows users only:
    # in cmd/bbctl/run.go, remove the following lines since msys2 is still seen as linux but Windows doesn't support Setpgid:

    # if runtime.GOOS == "linux" {
    #     cmd.SysProcAttr = &syscall.SysProcAttr{
    #         // Don't pass through signals to the bridge, we'll send a sigterm when we want to stop it.
    #         // Causes weird issues on macOS, so limited to Linux.
    #         Setpgid: true,
    #     }
    # }

    ./build.sh
    ```

2. Clone the repository:

    ```bash
    git clone https://github.com/highesttt/matrix-line-messenger.git
    cd matrix-line-messenger
    ```

3. Create a `data` directory for configuration and data storage:

    ```bash
    mkdir data
    ```

4. Create a configuration file using [bbctl](https://github.com/beeper/bridge-manager):

    ```bash
    bbctl c --type bridgev2 sh-line > config.yaml
    ```

5. Move the generated `config.yaml` into the `data` directory:

    ```bash
    mv config.yaml data/
    ```

6. Build and run the bridge using Docker (use -d for detached mode):

    - __Using Docker Compose:__

    ```bash
    docker compose up --build -d
    ```

    To run the bridge without rebuilding, use:

    ```bash
    docker compose up -d
    ```

    - __Building and running without Docker on Windows (MSYS2 and x86_64-w64-mingw32-gcc required)__

    ```bash
    # Clone and build olm if not already done
    git clone https://gitlab.matrix.org/matrix-org/olm.git
    cd olm
    cmake . -Bbuild
    cmake --build build
    cd ..

    # Build the bridge. Make sure to have the olm .dll file(s) in the root of the project.
    ./build_windows.sh
    cd data
    ../matrix-line.exe
    ```

    - __Other systems:__

    ```bash
    ./build.sh
    cd data
    ../matrix-line
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
