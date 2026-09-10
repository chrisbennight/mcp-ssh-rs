FROM rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build
WORKDIR /src

# Where crates come from. This stage reaches the network, and the fleet wants
# that traffic through its caching proxy - but Docker gives a RUN step an
# environment built from this file rather than the caller's, so the address has
# to arrive as a build argument.
#
# Cargo reads no environment variable for a mirror at all, so unlike pip or npm
# it cannot simply be told: the redirect has to be a config file, written from
# this value below. The name stays outside cargo's own CARGO_ namespace on
# purpose - cargo maps CARGO_REGISTRY_INDEX onto its removed registry.index key
# and aborts every invocation, and an ARG is visible to RUN as an environment
# variable, so that spelling would break the build it was meant to route.
#
# Left unsupplied it stays unset, no config file is written, and cargo resolves
# from crates.io. That fallback is what keeps this image buildable away from the
# network the proxy lives on.
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

# distroless: no shell and no package manager in the runtime image, so a
# command-injection defect in this service has no interpreter to reach for.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:adcd20c7b4c988b73cbfbddb26d2eee574571e6d7c9ffea29b3821e0690efb77
COPY --from=build /src/target/release/mcp-ssh-rs /mcp-ssh-rs
USER nonroot:nonroot
EXPOSE 8080
# The binary probes itself; the image ships nothing else that could.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/mcp-ssh-rs", "--healthcheck"]
ENTRYPOINT ["/mcp-ssh-rs"]
