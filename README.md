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

- Run on embedded (support for ESP-IDF (ESP32) & (hopefully) pico-sdk (Raspberry Pi
  Pico [W])).

- Be portable to any OS; empower any system to connect to XMPP networks.

- Be compatible with the major XMPP clients and servers (Prosody guaranteed).

- Low amount of code while still being readable.

- Control of memory usage (when possible).

### Non-goals

- Implement the XMPP spec word-for-word.

- Have an extension/plugin system, for additional features you must
  patch the library.

## XMPP Compliance

- RFC-6120 (Core): Partial.

- RFC-7590 (TLS): Partial, full planned.

- XEP-0198 (Stream Management): Mostly.

  * Location and (C-\>S) max attributes not supported.

- XEP-0199 (XMPP Ping): Partial. TODO: remove this.

  * Received ping's are returned unless disabled.

## OMEMO

 `omemo.c` contains implementations of X3DH, Double Ratchet and
 Protobuf with an API that is specifically tailored to OMEMO. We do not
 have dependencies on (any) libsignal or libolm code.

 Curve25519 and Ed25519 functions are handled by the c25519 library,
 which is included as amalgamation in `/c25519.c` and `/c25519.h`. Some
 changes have been made there which can be inspected with `$ git diff
 2eef25dc -- c25519.*`. This Curve25519 implementation is noticably
 slower than curve25519\_donna.

 The version of OMEMO implemented is 0.3.0, updating this library to a
 newer version of OMEMO should be trivial, but supporting multiple
 versions at once will probably make the code a mess.

## Dependencies

- MbedTLS 3.0+

- C99 compiler

- docker-compose (for testing)

## Usage

Running the tests:

 `$ make start-prosody`

 `$ make test`

Compile the esp-idf version of the im:

 `$ make esp-im`

Using this library for your own project:

 Copy over `/xmpp.c`, `/xmpp.h`, `/yxml.c` and `/yxml.h` to your
 project.

 If you want to use OMEMO, copy over `/omemo.c`, `/omemo.h`,
 `/c25519.c` and `/c25519.h`.

 In both cases, you must link against libmbedcrypto (and/or configure your
 mbedtls build to only include the needed functions TODO: specify
 which).

### Example

 The [`im.c`](./examples/im.c) example shows how additional
 functionality can be used in combination with the library. The example
 is not a feature complete instant messenger.

Run the im (instant messenger) example:

 `$ make runim`

 By default the localhost self-signed certificate is used. For a simple
 test you can spin up prosody (`$ make start-prosody`) and run the echo
 bot (`$ make start-omemo-bot`).

## License

 The new code in the library is licensed under ISC.

 yxml is licensed under MIT and c25519 is in the public domain.

 While not directly included, MbedTLS is dual-licensed under Apache-2.0
 or GPL-2.0-or-later.
