#!/usr/bin/env bash
set -euo pipefail
rust=false
audit=false
python=false
image=false
publish=false
tls=false
quickstart=false
case "${GITHUB_EVENT_NAME:?event is required}" in
  workflow_dispatch) full=true ;;
  pull_request|push) full=false ;;
  *) echo 'Unsupported CI event' >&2; exit 1 ;;
esac
if [[ "$GITHUB_EVENT_NAME" == push && "${GITHUB_REF:-}" == refs/tags/* ]]; then full=true; fi
if [[ "$full" == true ]]; then
  publish=true
  rust=true; audit=true; python=true; image=true; tls=true; quickstart=true
else
  [[ "${BASE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || { echo 'A full base commit is required' >&2; exit 1; }
  changed_files="$(mktemp)"
  trap 'rm -f "$changed_files"' EXIT
  if [[ "$GITHUB_EVENT_NAME" == pull_request ]]; then
    git diff --name-only --no-renames -z "$BASE_SHA...HEAD" >"$changed_files"
  else
    git diff --name-only --no-renames -z "$BASE_SHA" HEAD >"$changed_files"
  fi
  while IFS= read -r -d '' path; do
    case "$path" in
      .ci/changed-components.sh|.github/workflows/*) rust=true; audit=true; python=true; image=true; tls=true; quickstart=true ;;
      Cargo.toml|Cargo.lock|rust-toolchain.toml|rust-toolchain|crates/*/Cargo.toml) rust=true; audit=true; image=true; tls=true; quickstart=true ;;
      .cargo/audit.toml) audit=true ;;
      .cargo/*) rust=true; image=true; tls=true; quickstart=true ;;
      rustfmt.toml|.rustfmt.toml|clippy.toml|.clippy.toml) rust=true ;;
      crates/ssh-core/src/files/download/tests.rs|crates/ssh-server/src/dashboard_demo.rs|crates/*/tests/*|crates/*/benches/*|crates/*/examples/*) rust=true ;;
      crates/*/*.md) ;;
      crates/*) rust=true; image=true; tls=true; quickstart=true ;;
      Dockerfile|.dockerignore|LICENSE|NOTICE) image=true; tls=true; quickstart=true ;;
      .ci/audit.py) audit=true; python=true ;;
      .ci/smoke_image.py) image=true; python=true ;;
      .ci/verify_https.py) image=true; tls=true; python=true ;;
      .ci/verify_quickstart.py|examples/quickstart/*) image=true; quickstart=true; python=true ;;
      .ci/*) python=true ;;
    esac
    case "$path" in
      crates/ssh-core/src/files/download/tests.rs|crates/ssh-server/src/dashboard_demo.rs|crates/*/tests/*|crates/*/benches/*|crates/*/examples/*|crates/*/*.md) ;;
      Cargo.toml|Cargo.lock|rust-toolchain.toml|rust-toolchain|.cargo/config|.cargo/config.toml|crates/*|Dockerfile|.dockerignore|LICENSE|NOTICE) publish=true ;;
    esac
  done <"$changed_files"
fi
printf 'rust=%s\naudit=%s\npython=%s\nimage=%s\ntls=%s\nquickstart=%s\npublish=%s\n' \
  "$rust" "$audit" "$python" "$image" "$tls" "$quickstart" "$publish" >>"${GITHUB_OUTPUT:?output file is required}"
