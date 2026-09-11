# Contributing

Development takes place in [GitHub](https://github.com/chrisbennight/mcp-ssh-rs).
Work on a branch and open a pull request against `main`. Describe the problem,
the resulting behavior, and how you tested it. Do not include credentials or
private deployment configuration in a patch or diagnostic output.

## Local checks

Install Rust through rustup, then run these commands from the repository root.
The toolchain file selects the Rust version and components.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --locked
```

CI also checks `Cargo.lock` against the public RustSec advisory database. To
reproduce it locally, install the `cargo-audit` version pinned in
[CI](.github/workflows/ci.yml), then run `python3 .ci/audit.py` with Python 3.11
or newer. This fails on yanked dependencies and known vulnerabilities except
the version-bounded [RSA assessment](docs/dependency-security.md).
It does not require GitHub's
Dependabot alerts to be enabled. It runs when CI runs; it does not continuously
monitor an unchanged branch or prove that dependencies have no vulnerabilities.

Tests use loopback servers and generated keys. They must not contact real SSH
targets or use production credentials. Changes to behavior need a regression
test. Read the [design](docs/design.md) before changing authorization or execution.

To check the container, install Docker with a local Linux daemon, Python 3,
and OpenSSH's `ssh-keygen`, then run:

```sh
docker build --tag mcp-ssh-ci .
python3 .ci/smoke_image.py mcp-ssh-ci
python3 .ci/verify_quickstart.py mcp-ssh-ci
```

The smoke test uses a generated key, a disposable registry, and an isolated
container. It checks non-root execution, the built-in healthcheck, and liveness
with a read-only filesystem and no external network. It does not test an
authenticated MCP session or a real SSH target.

The separate Quickstart check starts a disposable SSH target and exercises the
real MCP route, a permitted command, a held command, the separate operator
login, cross-origin refusal, result collection, and audit identities. It removes
its containers and generated credentials afterward. Stop an existing tutorial
before running it; the check refuses to reuse `.quickstart/`.

## GitHub checks and images

[CI](.github/workflows/ci.yml) runs `audit`, `test`, and `verify-image` on pull requests
and pushes to `main`, using GitHub-hosted runners and public dependencies.
The Dockerfile's optional crate mirror is not required by CI.

After all checks pass on a push to `main`, `publish` builds and checks its own
image, then pushes `ghcr.io/chrisbennight/mcp-ssh-rs:sha-<full-commit-sha>`.
Only that job receives package-write permission. It uses the workflow's
`GITHUB_TOKEN`; no Infisical credentials or deployment webhook are needed.
It reads the image back from GHCR and checks its image ID. Use the reported
digest for an exact deployment: rerunning the same commit can replace its SHA
tag. There is no moving `latest` tag or automatic deployment to a host.

The repository is private during preparation. Newly created GHCR packages are
private by default; maintainers should verify package access separately before
sharing a pull command. Repository visibility does not itself publish a package.

## Maintainer setup

GitHub repository settings and installed apps are managed separately from the
checked-in workflow. Before merging, configure a rule for `main` requiring a
pull request, up-to-date branches, `audit`, `test`, `verify-image`, and `pr-review/gate`.
Restrict force pushes and deletion. Do not require `publish` on PRs: it runs
only after a push to `main`.

AERB supplies the review status. Its configuration remains in
[`.gitea/pr-review/policy.yaml`](.gitea/pr-review/policy.yaml), the path its
loader uses, despite GitHub hosting the repository. Give the AERB installation
access to this repository and verify that a review posts `pr-review/gate` on
the current PR commit before requiring that status.

Give the chosen Renovate installation access to this private repository.
[Renovate configuration](renovate.json) covers Cargo, Docker, GitHub Actions,
and the Rust toolchain. It retains the existing security-only Cargo update
policy. Installing an app and configuring branch rules are not performed by CI.

The imported Gitea deployment workflow has been removed from this GitHub
checkout. Existing lab deployment remains managed separately; changing the
lab to consume GHCR requires its own deployment change.
