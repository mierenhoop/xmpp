## Notice

 In this stage of the project, superior ways-of-doing-things might be
 found in the near future which can make the API unstable. The code
 also needs more real-world- and unit-tests, so do not use this for
 critical production software. Also, do not dynamically link with the
 expectation you can swap with a newer version. Please report any bugs
 when found.

## About

This library only supports the bare minimum framework for keeping track
of an XMPP session. The `im.c` example shows how additional
functionality can be used in combination with the library. The example
is not a feature complete instant messenger.

Uses:

- Instant messenger.

- Easy integration of Iot device with existing XMPP software.

- Pub-Sub client for e.g. RSS.

- Integrating chat into a video game.

Goals:

- Run on embedded (support for ESP-IDF (ESP32) & (hopefully) pico-sdk (Raspberry Pi
  Pico [W])).

- Be portable to any OS. Empower any system to connect to XMPP networks.

- Support non-embedded (Desktop, etc.) too.

- Be compatible with the major XMPP servers (Prosody guaranteed).

- Don't allow unusual or malicious data sent from a server.

- Be very fast.

- Low amount of code while still being readable.

- Don't expect the programmer (consumer of this API) to be stupid.

- Extreme control of memory (when possible).

- Have the modern XMPP features available.

Non-goals:

- Implement the XMPP spec word-for-word.

- Have an extension/plugin system, for additional features you must
  patch the library.

## XMPP Compliance

- RFC-6120 (Core): Partial.

- RFC-7590 (TLS): Partial, full planned.

- XEP-0198 (Stream Management): Mostly.

  * Location and (C-\>S) max attributes not supported.

- XEP-0199 (XMPP Ping): Partial.

  * Received ping's are returned unless disabled.

## OMEMO

 `/omemo.c` contains implementations of X3DH, Double Ratchet and
 Protobuf with an API that is specifically tailored to OMEMO. We do not
 have dependencies on (any) libsignal or libolm code.

 Curve25519 and Ed25519 functions are handled by the c25519 library,
 which is included as amalgamation in `/c25519.c` and `/c25519.h`. Some
 changes have been made there which can be inspected with `$ git diff
 2eef25dc -- c25519.*`.

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

Run the im (instant messenger) example:

 `$ make runim`

Compile the esp-idf version of the im:

 `$ make esp-im`

Using this library for your own project:

 Copy over `/xmpp.c`, `/xmpp.h`, `/yxml.c` and `/yxml.h` to your
 project.

 If you want to use OMEMO, copy over `/omemo.c`, `/omemo.h`,
 `/curve25519.c` and `/curve25519.h`.

 Either way, you must link against libmbedcrypto (and/or configure your
 mbedtls build to only include the needed functions TODO: specify
 which).

## License

 The new code in the library is licensed under ISC.

 yxml is licensed under MIT and c25519 is in the public domain.

 While not directly included, MbedTLS is dual-licensed under Apache-2.0
 or GPL-2.0-or-later.
