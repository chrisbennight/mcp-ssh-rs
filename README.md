# mcp-ssh-rs

An MCP service that lets AI agents run commands on configured hosts over SSH,
under policy, with a reviewable record of what they did and a human in the loop
for anything consequential.

**Status: active implementation.** The mediated SSH path, policy and audit
chain, human review queue, bounded sessions, and operations dashboard are
implemented; rollout and further hardening are tracked in linked issues.

## Why it exists

Agents working on this fleet currently have two options and both are bad. Most
have no host access at all, so a human SSHes in and pastes output back — the
single biggest source of friction in day-to-day debugging. The alternative is
handing the agent a private key, which is an unaudited, unconstrained
credential sitting inside the blast radius.

This service is the third option: the agent asks for work to be done on a host,
and the service does it.

## The problems it addresses

- **Relayed output.** Diagnosing a host currently means a human runs commands
  and pastes results back to the agent.
- **All-or-nothing trust.** Giving an agent a key is a single irreversible
  decision made once, in advance, covering everything that key can reach.
- **Reconstructing what happened.** Terminal recordings are the usual artifact,
  and answering a question from them means watching them.
- **Interruption cost.** Asking a human about every command trains everyone to
  approve without reading.

What the service actually guarantees against each of these is defined in
`docs/design.md`, not here.

## Documentation

- [Security reports](SECURITY.md) — how to request a private reporting channel.
- [Preparing a public release](docs/releases.md) — snapshot and distribution checks.
- [Dependency security](docs/dependency-security.md) — advisory assessment and
  RSA credential compatibility.
- [Contributing](CONTRIBUTING.md) — local checks, GitHub CI, image publication,
  and maintainer setup.
- **`docs/design.md`** — intent, trust boundaries, component responsibilities,
  and the decisions behind them. Read its **non-goals** section first. Several
  plausible-sounding features are excluded deliberately, and that boundary is
  the part most likely to be eroded.

The design deliberately does not specify tool signatures, policy syntax,
storage layout, or wire formats. Those belong in code and tests, where they can
be validated.

## Optional advisory evaluator

An external evaluator can append immutable evidence to a recorded command
decision when its current bearer and deployment-owned name are supplied.
An optional previous bearer supports rotation. Evaluator credentials must be
distinct from gateway and dashboard credentials; partial configuration is
refused, and with no evaluator configured the ingestion route is not mounted.
The exact environment variable names and validation rules are documented by
`ssh_server::settings::Settings`. Evaluations never authorize execution.

## Durable dashboard history

Audit and evaluation pages can read bounded, cursor-paginated history from the
deployment's existing log store through the optional audit-query setting. The
service does not copy that history into another store. If the reader is absent,
times out, returns malformed data, or exceeds its response bound, those pages
say the durable source is unavailable instead of substituting process-local or
stale data. Operators can filter that history by bounded time window, recorded
risk and verdict, and structured identity fields. The configured host/role
inventory and current Sessions page remain explicitly live process views; both
session cards and historical rows link to a durable session transcript that
pages by command and joins each selected decision with its human answer and
authorization, observed outcome, and advisory evaluation by their recorded
identifiers. Related evidence is resolved across the transcript's raw source
pages rather than disappearing when it landed on the other side of a cursor.
The transcript is not approval-driven: policy-permitted commands and commands
released after approval both carry their recorded completion and response;
denied decisions remain visible as attempts that did not run. Each kept stdout
and stderr preview links to an authenticated detail view that reads the exact
session and run from the same bounded source window and shows every byte the
execution record retained. Capture truncation and secret-shaped withholding
remain explicit; the detail view cannot recover bytes the execution path did
not retain.

New evaluation entries carry the bounded command, agent intent, session
purpose, and recorded decision assessment they evaluate, so verdict- or
assessment-filtered history remains self-contained; older entries label context
that predates this shape as unavailable.

## License

MIT
