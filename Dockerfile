FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
WORKDIR /src

# Optional operator-supplied Cargo mirror. Without it, builds use crates.io.
# Cargo source replacement keeps the lockfile tied to the public registry.
ARG CRATES_INDEX_URL

COPY . .

# Source replacement rather than an additional registry: it redirects the
# existing crates.io source instead of introducing a second one, so Cargo.lock
# goes on naming crates-io and a lock produced here still resolves from the
# public index.
RUN if [ -n "${CRATES_INDEX_URL}" ]; then \
      mkdir -p .cargo && \
      printf '[source.crates-io]\nreplace-with = "mirror"\n\n[source.mirror]\nregistry = "%s"\n' \
        "${CRATES_INDEX_URL}" > .cargo/config.toml; \
    fi

# --locked so a build cannot silently resolve a different dependency graph than
# the one that was reviewed.
RUN cargo build --release --locked --bin mcp-ssh-rs

# The non-root runtime image contains the service and its shared libraries.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/mcp-ssh-rs /mcp-ssh-rs
COPY LICENSE NOTICE /usr/share/doc/mcp-ssh-rs/
LABEL org.opencontainers.image.licenses="Apache-2.0"
USER nonroot:nonroot
EXPOSE 8080
# The binary probes itself; the image ships nothing else that could.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/mcp-ssh-rs", "--healthcheck"]
ENTRYPOINT ["/mcp-ssh-rs"]
