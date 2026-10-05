# Official Rust multi-platform index verified from Docker Hub on 2026-10-05.
# Tests and final compilation are offline after a locked public-registry fetch.
FROM rust:1.93.0-alpine@sha256:69d7b9d9aeaf108a1419d9a7fcf7860dcc043e9dbd1ab7ce88e44228774d99e9 AS build
WORKDIR /build
ENV CARGO_BUILD_JOBS=2
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo fetch --locked
RUN --network=none set -eu; \
    cargo test --locked --offline --release; \
    cargo build --locked --offline --release; \
    readelf -l target/release/wiskit-gateway-inert > /tmp/program-headers; \
    if grep -q INTERP /tmp/program-headers; then echo 'Refusing dynamically linked binary'; exit 1; fi

FROM scratch
COPY --from=build /build/target/release/wiskit-gateway-inert /gateway
USER 65532:65532
ENV WISKIT_GATEWAY_MODE=deny-all
EXPOSE 8080/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/gateway", "--healthcheck"]
ENTRYPOINT ["/gateway"]
