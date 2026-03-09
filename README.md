# matrix-line-messenger

[![Go Report Card](https://goreportcard.com/badge/github.com/highesttt/matrix-line-messenger)](https://goreportcard.com/report/github.com/highesttt/matrix-line-messenger)
![Languages](https://img.shields.io/github/languages/top/highesttt/matrix-line-messenger.svg)
[![License](https://img.shields.io/github/license/highesttt/matrix-line-messenger.svg)](LICENSE)

A Matrix bridge for LINE Messenger using mautrix-go.\
Based on the [mautrix-twilio](https://github.com/mautrix/twilio) bridge

> [!WARNING]
> When updating from a version released before February 14, 2026,
> please make sure to reset your configuration and log in again.
> This is due to a change in the login flow that requires users to log
> in again to fetch the necessary keys for E2EE decryption.

## Known issues

> [!NOTE]
> Messages sent to the LINE Bot using Beeper Desktop may appear as
> indefinitely sending.
> Use Beeper Mobile to send commands to the LINE Bot account after
> creating the chat with Beeper Desktop.

## Features

- [x] Messages (Text, Images, Videos, voice notes and any other kind of files)
- [x] Read receipts
- [x] Reaction support (Receive ONLY)
- [x] Replies
- [x] Prefetch missed chats upon starting the bridge
- [x] Group chats
- [x] Sticker retrieval support
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

    - Ensure you have [Docker](https://www.docker.com/get-started/)
      and [Docker Compose](https://docs.docker.com/compose/install/)
      installed on your system.
    - If you want to build and run without Docker, ensure you have Go
      installed along with the necessary build tools, such as the olm
      library and `bbctl`.

    - Compile bbctl from source if you don't have it already:

    ```bash
    git clone https://github.com/beeper/bridge-manager.git
    cd bridge-manager

    # For windows users only:
    # In cmd/bbctl/run.go, remove the following lines because MSYS2 is
    # still seen as Linux, but Windows doesn't support Setpgid:

    # if runtime.GOOS == "linux" {
    #     cmd.SysProcAttr = &syscall.SysProcAttr{
    #         // Don't pass through signals to the bridge.
    #         // We'll send a sigterm when we want to stop it.
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

    - __Building and running without Docker on Windows__
      (MSYS2 and `x86_64-w64-mingw32-gcc` required)

    ```bash
    # Clone and build olm if not already done
    git clone https://gitlab.matrix.org/matrix-org/olm.git
    cd olm
    cmake -Bbuild -G "Unix Makefiles" \
      -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
      -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
      -DCMAKE_INSTALL_PREFIX=/mingw64
    cmake --build build
    cmake --install build
    cd ..
    # Move the .dll and .dll.a files in the matrix-line root directory

    # Build the bridge. Make sure the olm .dll file(s) are in the root
    # of the project.
    ./build-windows.sh
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

1. Open the Matrix client of your choice and start a chat with
   `@sh-linebot:your.matrix.homeserver.domain`. For local Beeper
   bridges, use `@sh-linebot:beeper.local`.
2. Send the command `login` and follow the instructions to log in to your LINE account.

or

### Via Beeper Desktop Settings

1. Open Beeper Desktop Settings
2. Navigate to `Bridges`
3. Click the three dots next to your LINE Bridge and select
   `Experimental: Add an account`
4. Follow the instructions to log in to your LINE account.

## Can't log in?

There are two common reasons login can fail:

### 1. No email is set on your LINE account

This bridge uses the email from your account information. If your
account is older, you signed in using a phone number, or you signed in
with Google, you may not have an email set for your LINE account.

__How to set an email for your LINE account:__

1. Open the LINE app on your mobile device.
2. Go to `Settings` > `Account`.
3. Tap on `Email address` and set your email address.

### 2. Letter Sealing (End-to-End Encryption) is disabled

This bridge requires LINE's end-to-end encryption feature,
`Letter Sealing`, to be enabled. If it is disabled, the login will fail
with `Error when logging in: Internal error`.

__How to enable Letter Sealing:__

1. Open the LINE app on your mobile device.
2. Go to `Settings` > `Privacy`.
3. Turn `Letter Sealing` on (note: it can't be turned off once you do so)
4. Try logging in to the bridge again.

> [!NOTE]
>
> - The `Letter Sealing` setting is only configurable from the LINE
>   mobile app.
> - `Letter Sealing` was introduced as an optional feature in August 2015.
> - It was enabled by default in major LINE clients in 2016.
> - Since 2021, it has been enabled by default in all regions and can no
>   longer be turned off manually.
> - For more information, see
>   [issue #42](https://github.com/highesttt/matrix-line-messenger/issues/42).
