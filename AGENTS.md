# AGENTS.md

Instructions for coding agents working in `mcp-ssh-rs`.

## Purpose

An MCP service for SSH commands and binary file transfer through configured
accounts, with optional human review. What it
guarantees, and what it deliberately does not, is defined in the design rather
than summarized here.

`docs/design.md` is the **sole normative document**: intent, trust boundaries,
component responsibilities, and decisions that would be expensive to reverse.
Read its non-goals section before proposing work — several attractive-sounding
features are deliberately excluded.

The design deliberately does not specify tool signatures, policy syntax,
storage layout, or wire formats. That is implementation, and it belongs in code
and tests where it can be validated. Do not add it to the design to "write it
down first" — prose specifications are unvalidated and drift.

## Workflow

- Never work directly in the main checkout. Fetch `main` from the GitHub
  remote, create a dedicated branch and an ignored `.worktrees/` worktree,
  and work there. Verify the remote URL before fetching or pushing.
- Use the GitHub MCP for repository, pull-request, and Actions operations.
  Use local Git for checkouts, commits, and pushes.
- Do not commit, push, open, or merge a PR without explicit user
  authorization. A direct invocation of the `pr-and-monitor` skill supplies
  that authorization for its complete loop.
- Before opening or updating a PR, review the candidate diff for security,
  validation, and documentation drift. Use `pre-pr-review` when available;
  contributors do not need private skills to submit a change.
- Every PR must use `.github/PULL_REQUEST_TEMPLATE.md`.
- A PR may merge only when required CI is green and AERB has no unresolved
  findings.

See [Contributing](CONTRIBUTING.md) for the development and CI workflow.

## Security constraints

The invariants this service exists to uphold are stated once, in
`docs/design.md`. Read them there.
Treat a change that weakens one as a defect regardless of what else it
improves.

**Do not restate those invariants here, in the review policy, or in another
document** — not even as a convenience summary, and not even correctly. A prose
rule copied into two places drifts, and the drift itself then reads as a
security defect. Where a property needs to be pinned down, pin it in code and
in a test that fails if the property regresses. That is the only copy that
earns its place, because it is the only one that can be wrong out loud.

## Rust checks

Run these from the repository root and require explicit success:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --locked
```

Every behavioral change must have a test that would fail if the production
change were reverted. Tests may not use real SSH targets, real credentials,
the network, or anything that costs money; use loopback servers and fakes.

## Documentation

For visual assets, documentation presentation, or application UI changes, read
[the visual identity guide](docs/branding/README.md) and use its checked-in
reference and production assets. It covers appearance; product and security
decisions remain in `docs/design.md`.

Keep `README.md` and `docs/design.md` aligned with implemented behavior.
Documentation references must use symbols or headings rather than line
numbers. When the design and the code disagree, say so in the PR rather than
silently letting the doc rot.
