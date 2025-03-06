## Notice

Do not use the code in this repository for anything serious yet; there
might be unidentified security vulnerabilities present. You are
encouraged to report such issues when found.

## About

The file `omemo.c` contains a compact implementation of OMEMO.

### Goals

- Run on embedded: support for ESP32 on ESP-IDF & Raspberry Pi Pico
  \[W\] on pico-sdk (untested).

- Be portable to any OS.

- Work with all relevant clients that have OMEMO.

- Low amount of code while still being readable.

- Control of memory management.

### Non-goals

- Support multiple OMEMO versions at once.

## OMEMO

 `omemo.c` contains implementations of X3DH, Double Ratchet and
 Protobuf with an API that is specifically tailored to OMEMO. We do not
 have dependencies on (any) libsignal or libolm code.

 Curve25519 and Ed25519 functions are handled by the
 [c25519](https://www.dlbeer.co.nz/oss/c25519.html) library, which is
 included as amalgamation in `/c25519.c` and `/c25519.h`. Some changes
 have been made there which can be inspected with `$ git diff 2eef25dc
 -- c25519.*`. This Curve25519 implementation is noticably slower than
 curve25519\_donna. Decrypting messages can take hundreds of
 milliseconds to seconds and filling a hundred prekeys can take up to
 minutes on microcontrollers. To speed things up, [cosmopolitan's
 overhaul](https://github.com/jart/cosmopolitan/blob/master/third_party/mbedtls/everest.c)
 of the [Everest](https://project-everest.github.io/) Curve25519
 implementation is enabled on supported systems.

 The version of OMEMO implemented is 0.3.0, updating this library to a
 newer version of OMEMO should be trivial, but supporting multiple
 versions at once will probably make the code a mess.

## Dependencies

- MbedTLS 3.0+

- C99 compiler

- docker-compose (for testing)

## Usage

Running the tests:

 `$ make test-omemo`

Using this library for your own project:

If you want to use OMEMO, copy over `/omemo.c`, `/omemo.h`,
`/c25519.c` and `/c25519.h`.

You must link against libmbedcrypto (and/or configure your mbedtls build
to only include the needed functions.

### Example

The [`im.c`](./example/im.c) example shows how additional
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
$ cat > example/esp-im/config.h <<EOF
#define IM_WIFI_SSID "ssid"
#define IM_WIFI_PASS "password"
#define IM_SERVER_IP "192.168.1.2"
EOF
```

`$ make esp-im`

`$ ESP_DEV=/dev/ttyUSB0 make esp-upload`

`$ ESP_DEV=/dev/ttyUSB0 make esp-monitor`

### Demo of XMPP with OMEMO on an ESP32

https://github.com/user-attachments/assets/b01d9439-f30b-4062-8711-02cbf9599e67

## License

The code in this repository is licensed under ISC, all vendored code in
this repository is also permissively licensed:

yxml is licensed under MIT, c25519 is in the public domain and
Everest Curve25519 is licensed under Apache-2.0.

While not directly included, MbedTLS is dual-licensed under Apache-2.0
or GPL-2.0-or-later.
