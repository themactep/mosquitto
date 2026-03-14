# Building Mosquitto with mbedtls

Mosquitto can be built with the mbedtls TLS backend when using the CMake build.
The plain `make` build controlled by `config.mk` does not provide a TLS backend
selection option, so use CMake for mbedtls builds.

## Dependencies

You need the normal Mosquitto build dependencies plus the mbedtls development
packages with `pkg-config` metadata.

On Debian/Ubuntu systems this is typically:

```sh
sudo apt install build-essential cmake pkg-config libcjson-dev libmbedtls-dev
```

If you are building from a git checkout and want the man pages as well, install
the documentation dependencies described in `README-compiling.md`. Otherwise you
can disable man page generation with `-DWITH_DOCS=OFF`.

## Configure

Create a separate build directory and configure CMake to use mbedtls:

```sh
cmake -S . -B build-mbedtls \
  -DWITH_TLS=ON \
  -DWITH_TLS_BACKEND=mbedtls \
  -DWITH_TLS_PSK=OFF \
  -DWITH_WEBSOCKETS=OFF \
  -DWITH_DOCS=OFF
```

`WITH_TLS_PSK=OFF` and `WITH_WEBSOCKETS=OFF` are currently required with the
mbedtls backend because those code paths still rely on OpenSSL-specific APIs in
this tree.

If you want to keep the default documentation build, remove `-DWITH_DOCS=OFF`
and install the documentation tools first.

## Build

Build everything with:

```sh
cmake --build build-mbedtls
```

To install after a successful build:

```sh
sudo cmake --install build-mbedtls
```

## Verify the configuration

During configuration, CMake should report that it found the three mbedtls
packages:

```text
-- Checking for modules 'mbedtls;mbedx509;mbedcrypto'
--   Found mbedtls, version ...
--   Found mbedx509, version ...
--   Found mbedcrypto, version ...
```

If CMake cannot find those packages, make sure the mbedtls development package
is installed and that `pkg-config` can locate `mbedtls.pc`, `mbedx509.pc`, and
`mbedcrypto.pc`.
