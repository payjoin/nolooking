# Multistage Build for Nolooking
#
# x86_64-unknown-linux-musl
# aarch64-unknown-linux-musl
#
# Conditionally `cargo build` for platforms of x86_64 or ARM.
# Use musl for static linking, producing a standalone executable with no dependencies.
# In the final Docker stage we copy the built binary to alpine, and run with environment:
# $LND_HOST, $LND_GRPC_PORT, $TLS_FILE, $MACAROON_FILE"

## Initial build Stage
FROM rustlang/rust:nightly AS builder
# Target architecture argument used to change build
ARG TARGETARCH
# Some nicer rust debugging
ENV RUSTFLAGS="-Z macro-backtrace"
ENV RUST_BACKTRACE=1
# Copy the required build files. In this case, these are all the files that
# are used for both architectures.
WORKDIR /usr/src/nolooking/
COPY Cargo.toml Cargo.lock build.rs config_spec.toml ./
COPY src/ ./src/

## x86_64
FROM builder AS branch-version-amd64
RUN echo "Preparing to cargo build for x86_64 (${TARGETARCH})"
# Install the required dependencies to build for `musl` static linking
RUN apt-get update && apt-get install -y musl-tools musl-dev
# Add our x86 target to rust, then compile and install
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo --config "net.git-fetch-with-cli=true" install  -F "vendored" --target x86_64-unknown-linux-musl --path .

# ARM
FROM builder AS branch-version-arm64
RUN echo "Preparing to cargo build for arm (${TARGETARCH})"
# Install the required dependencies to build for `musl` static linking for arm.
RUN apt-get update && apt-get install musl-tools clang llvm -y
# Add our arm target to rust, some build variables, then compile and install
RUN rustup target add aarch64-unknown-linux-musl
ENV CC_aarch64_unknown_linux_musl=clang
ENV AR_aarch64_unknown_linux_musl=llvm-ar
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-Clink-self-contained=yes -Clinker=rust-lld"
RUN cargo --config "net.git-fetch-with-cli=true" install  -F "vendored" --target aarch64-unknown-linux-musl --path .

# We build for either x86_64 or ARM from above options using the docker $TARGETARCH
FROM branch-version-${TARGETARCH} AS chosen_builder
RUN echo "Called build!"

# Run nolooking from a final debian container
FROM debian:buster-slim
USER 1000

# Copy just the binary from our build stage
COPY --from=chosen_builder /usr/local/cargo/bin/nolooking /usr/local/bin/nolooking
COPY run_nolooking /usr/local/bin/run_nolooking
COPY --chown=1000:1000 public/ /usr/share/nolooking/public/

# Expose any necessary ports
EXPOSE 4444
# Run
CMD ["run_nolooking"]
