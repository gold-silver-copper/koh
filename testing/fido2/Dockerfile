# Self-contained end-to-end FIDO2 / security-key test for koh.
#
# Bakes three things into one image so the test needs no host setup beyond Docker:
#   1. OpenSSH built from source (its ssh-keygen/ssh-agent/ssh-add support security keys), plus
#      sk-dummy.so — OpenSSH's *software* FIDO2 authenticator (used by the OpenSSH project itself to
#      test sk keys without hardware). This lets us drive koh's real ssh-agent signing path.
#   2. A Rust toolchain.
#   3. The `koh` binary, built from the surrounding checkout.
#
# Build context is the repository root (see run.sh); a .dockerignore keeps it lean.
FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      git build-essential autoconf automake libssl-dev zlib1g-dev ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# --- OpenSSH + software FIDO2 authenticator (sk-dummy) ------------------------------------------
# We build vanilla OpenSSH (no libfido2 needed: sk-dummy is an *external* SecurityKeyProvider loaded
# via `ssh-keygen -w`, which replaces the USB/HID authenticator entirely). sk-dummy signs in software
# and echoes the user-presence flag the agent requests, so koh's touch requirement is satisfied.
ARG OPENSSH_TAG=V_9_9_P2
RUN git clone --depth 1 -b ${OPENSSH_TAG} https://github.com/openssh/openssh-portable /opt/openssh \
 && cd /opt/openssh \
 && autoreconf \
 && ./configure > /tmp/openssh-configure.log 2>&1 \
 && make -j"$(nproc)" > /tmp/openssh-make.log 2>&1 \
 && cc -fPIC -shared -I. -DWITH_OPENSSL \
      -o /opt/openssh/sk-dummy.so \
      regress/misc/sk-dummy/sk-dummy.c ed25519.o hash.o -lcrypto
ENV PATH=/opt/openssh:$PATH
ENV SSH_SK_HELPER=/opt/openssh/ssh-sk-helper
ENV SK_PROVIDER=/opt/openssh/sk-dummy.so

# --- Rust toolchain ----------------------------------------------------------------------------
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH=/root/.cargo/bin:$PATH

# --- Build koh from the checkout ---------------------------------------------------------------
# Copy only what the crate needs to build so unrelated churn doesn't bust the cache.
WORKDIR /koh
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
 && install -m 0755 target/release/koh /usr/local/bin/koh \
 && rm -rf target

# --- Test harness ------------------------------------------------------------------------------
COPY testing/fido2/harness /koh/harness
RUN chmod +x /koh/harness/run-tests.sh
ENTRYPOINT ["/koh/harness/run-tests.sh"]
