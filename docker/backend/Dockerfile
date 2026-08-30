# The backend image: the stock .NET SDK, plus a PKCS#11 module for the YubiHSM.
#
# The module has to exist inside this container, and it has to match the
# container's architecture -- which is the participant's architecture, since
# Docker resolves mcr.microsoft.com/dotnet/sdk:10.0 to linux/amd64 on Windows and
# Intel Macs and to linux/arm64 on Apple Silicon.
#
# Yubico publishes a Linux build for amd64 only. Ubuntu does not package
# yubihsm-shell at all (Debian does, but not for the noble this image is built
# on). So we compile it, which is the one approach that needs no per-architecture
# branching: the source is plain cmake and builds identically on both.
#
# Build and publish for both, so that a participant only ever pulls:
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#       -t abratanov/medsign-backend:latest --push docker/backend
#
# `docker compose up` falls back to building it locally for one architecture if
# the published image cannot be pulled.

# ---- The module ------------------------------------------------------------

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS pkcs11

ARG YUBIHSM_SHELL_VERSION=2.8.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake gengetopt pkg-config curl ca-certificates \
        libssl-dev libcurl4-openssl-dev libedit-dev libusb-1.0-0-dev \
        libpcsclite-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/Yubico/yubihsm-shell/archive/refs/tags/${YUBIHSM_SHELL_VERSION}.tar.gz" \
        -o /tmp/yubihsm-shell.tar.gz \
    && mkdir -p /tmp/src \
    && tar -xzf /tmp/yubihsm-shell.tar.gz -C /tmp/src --strip-components=1

# CMAKE_INSTALL_PREFIX=/usr is what lands the module on /usr/lib/pkcs11, which is
# the path Hsm__ModulePath already defaults to. Manpages are skipped because they
# would pull in help2man for a library nobody reads the manpage of.
RUN cmake -S /tmp/src -B /tmp/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DWITHOUT_MANPAGES=1 \
        -DCMAKE_INSTALL_PREFIX=/usr \
    && cmake --build /tmp/build -j"$(nproc)" \
    && cmake --install /tmp/build \
    && test -f /usr/lib/pkcs11/yubihsm_pkcs11.so

# ---- The backend -----------------------------------------------------------

FROM mcr.microsoft.com/dotnet/sdk:10.0

# The module needs libcrypto, libcurl and zlib, which the SDK image already has,
# and these two, which it does not. libpcsclite is linked by the module itself
# (for YubiKey HSM Auth); libusb is needed by libyubihsm_usb, which libyubihsm
# opens at runtime when it is asked for a usb:// connector.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcsclite1 libusb-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# The module, and the libraries it links and dlopens. libyubihsm_http and
# libyubihsm_usb are opened by name at runtime, so they have to be here even
# though nothing links them.
COPY --from=pkcs11 /usr/lib/pkcs11/ /usr/lib/pkcs11/
COPY --from=pkcs11 /usr/lib/libyubihsm.so* /usr/lib/libyubihsm_http.so* \
                   /usr/lib/libyubihsm_usb.so* /usr/lib/libykhsmauth.so* /usr/lib/

# Pkcs11Interop reaches the module through dlopen, which it P/Invokes as
# [DllImport("libdl")]. glibc 2.34 merged libdl into libc and left libdl.so.2
# behind as a compatibility stub, so a plain `libdl.so` -- the only name .NET
# probes for -- exists nowhere on Ubuntu 24.04, and the load fails with
# DllNotFoundException before the module is ever opened. Only the -dev packages
# ship that name, and pulling a toolchain into the runtime image to get one
# symlink is not a trade worth making. 5.3.0 is the current Pkcs11Interop, so
# there is no version to upgrade to that asks for libdl.so.2 instead.
#
# The path is read back from ldconfig rather than written out, because the
# directory is architecture-specific: x86_64-linux-gnu on amd64, and
# aarch64-linux-gnu on arm64.
RUN set -eux; \
    libdl="$(ldconfig -p | awk '/libdl\.so\.2/ { print $NF; exit }')"; \
    test -n "$libdl"; \
    ln -sf "$(basename "$libdl")" "$(dirname "$libdl")/libdl.so"

RUN ldconfig

WORKDIR /src
