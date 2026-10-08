# Official Rust multi-platform index verified from Docker Hub on 2026-10-05.
# Final compilation is offline after a locked public-registry fetch.
FROM rust:1.93.0-alpine@sha256:69d7b9d9aeaf108a1419d9a7fcf7860dcc043e9dbd1ab7ce88e44228774d99e9 AS build
WORKDIR /build
# Parallel rustc jobs: 2 keeps a small shared host responsive; the GitHub image
# build passes 4 (its runners have the cores and nothing else to serve).
ARG BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${BUILD_JOBS} \
    OPENSSL_STATIC=1
# webauthn-rs needs OpenSSL; link it statically so the final image stays FROM scratch.
# rusqlite builds its bundled SQLite with the C compiler.
RUN apk add --no-cache gcc musl-dev openssl-dev openssl-libs-static pkgconf
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
COPY tests ./tests
# config/routes.toml is also compiled into a unit test (include_str!), not only copied into the image.
COPY config ./config
RUN cargo fetch --locked
# The test suite runs before merge (see AGENTS.md), not here: a release-mode test build
# doubled compile time and memory and got the build killed on the shared Coolify host.
# target/ is a BuildKit cache mount kept on the Coolify builder between deploys, so only
# changed crates recompile (a cold build of the iroh tree is long on the shared host).
# The cache is not part of the image, so the binary is copied out in this same step.
RUN --network=none --mount=type=cache,id=mcp-edge-target,target=/build/target set -eu; \
    cargo build --locked --offline --release --bin mcp-edge; \
    mkdir -p /out/data; \
    cp target/release/mcp-edge /out/mcp-edge; \
    readelf -l /out/mcp-edge > /tmp/program-headers; \
    if grep -q INTERP /tmp/program-headers; then echo 'Refusing dynamically linked binary'; exit 1; fi

FROM scratch
COPY --from=build /out/mcp-edge /mcp-edge
COPY config/routes.toml /etc/mcp-edge/routes.toml
# A new named volume mounted at /data inherits this ownership.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV EDGE_MODE=edge \
    EDGE_BIND=0.0.0.0:8080 \
    EDGE_DATA_DIR=/data \
    EDGE_ROUTES=/etc/mcp-edge/routes.toml
EXPOSE 8080/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/mcp-edge", "--healthcheck"]
ENTRYPOINT ["/mcp-edge"]
