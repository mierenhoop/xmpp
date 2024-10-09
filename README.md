## Notice

 Do not use the code in this repository for anything serious; there
 might be unidentified security vulnerabilities present. You are
 encouraged to report such issues when found.

## About

This repository contains two libraries:

- `xmpp.c`: a bare minimum framework for keeping track of an XMPP
  session.

- `omemo.c`: a compact implementation of OMEMO.

### Uses

- Instant messenger.

- Easy integration of IoT device with existing XMPP software.

- Integrating chat into a video game.

### Goals

- Run on embedded: support for ESP32 on ESP-IDF & Raspberry Pi Pico
  \[W\] on pico-sdk (untested).

- Be portable to any OS; empower any system to connect to XMPP networks.

- Be compatible with the major XMPP clients and servers (Prosody guaranteed).

- Low amount of code while still being readable.

- Control of memory management (when possible).

### Non-goals

- Implement the XMPP spec word-for-word.

- Have an extension/plugin system or support multiple versions of a
  protocol, for additional features you must patch the library.

## OMEMO

 `omemo.c` contains implementations of X3DH, Double Ratchet and
 Protobuf with an API that is specifically tailored to OMEMO. We do not
 have dependencies on (any) libsignal or libolm code.

 Curve25519 and Ed25519 functions are handled by the
 [c25519](https://www.dlbeer.co.nz/oss/c25519.html) library, which is
 included as amalgamation in `/c25519.c` and `/c25519.h`. Some changes
 have been made there which can be inspected with `$ git diff 2eef25dc
 -- c25519.*`. This Curve25519 implementation is noticably slower than
 curve25519\_donna. For this reason [cosmopolitan's
 overhaul](https://github.com/jart/cosmopolitan/blob/master/third_party/mbedtls/everest.c)
 of the [Everest](https://project-everest.github.io/) Curve25519
 implementation is enabled on x86 64-bit systems.

 The version of OMEMO implemented is 0.3.0, updating this library to a
 newer version of OMEMO should be trivial, but supporting multiple
 versions at once will probably make the code a mess.

## Dependencies

- MbedTLS 3.0+

- C11 compiler

- docker-compose (for testing)

## Usage

Running the tests:

 `$ make start-prosody`

 `$ make test`

Using this library for your own project:

 Copy over `/xmpp.c`, `/xmpp.h`, `/yxml.c` and `/yxml.h` to your
 project.

 If you want to use OMEMO, copy over `/omemo.c`, `/omemo.h`,
 `/c25519.c` and `/c25519.h`.

 In both cases, you must link against libmbedcrypto (and/or configure your
 mbedtls build to only include the needed functions.

### Example

 The [`im.c`](./examples/im.c) example shows how additional
 functionality can be used in combination with the library. The example
 is not a feature complete instant messenger and for simplicity's sake
 the code is full of hardcoded and spec deviating behaviour that should
 not represent a serious XMPP client.

Run the im (instant messenger) example:

 `$ make runim`

 By default the localhost self-signed certificate is used. For a simple
 test you can spin up prosody (`$ make start-prosody`) and run the echo
 bot (`$ make start-omemo-bot`).

Compile the esp-idf version of the im:

```bash
$ cat > examples/esp-im/config.h <<EOF
#define IM_WIFI_SSID "ssid"
#define IM_WIFI_PASS "password"
#define IM_SERVER_IP "192.168.1.2"
EOF
```

 `$ make esp-im`

 `$ ESP_DEV=/dev/ttyUSB0 make esp-upload`

 `$ ESP_DEV=/dev/ttyUSB0 make esp-monitor`

## License

 The code in this repository is licensed under ISC, all vendored code in
 this repository is also permissively licensed:

 yxml is licensed under MIT, c25519 is in the public domain and
 Everest Curve25519 is licensed under Apache-2.0.

 While not directly included, MbedTLS is dual-licensed under Apache-2.0
 or GPL-2.0-or-later.
