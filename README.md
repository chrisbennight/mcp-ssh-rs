# mcp-ssh-rs

An MCP service that runs SSH commands on configured hosts, with command policy,
a reviewable execution record, and human approval when required. MCP (Model
Context Protocol) lets an AI client call these operations as tools.

**Status: preparing the first public release.** Development currently takes
place in this private GitHub repository. The initial supported setup is a
personal Linux/container deployment in one administrative domain.

## Try it

Follow the [local Quickstart](docs/quickstart.md). It builds the service and a
disposable SSH target, generates credentials, and shows this sequence:

1. A client opens a session and runs `whoami`.
2. A request to create a file waits for human approval.
3. The operator reviews it in the browser, and the client collects the result.

No gateway, identity provider, or private lab service is required for standalone
mode. The tutorial uses public build dependencies and a small Python MCP client.

## What is available

- Host and role discovery, bounded sessions, command execution, result polling,
  and session closure through MCP.
- Explicit account access classes, checked against configuration and session
  ownership on MCP session operations.
- Cedar command policy and a browser queue for held commands.
- Verified SSH host keys and target credentials supplied by the operator.
- Structured execution logs, with optional Loki history and notification adapters.
- Explicit standalone authentication, or the existing gateway integration with
  signed identity assertions.

File-transfer integration, OAuth login, independent tenants, and active replicas
are outside the initial supported setup. The service does not provision target
accounts or their permissions. Read the [design's non-goals and preconditions](docs/design.md#1-non-goals--read-this-first)
before connecting real hosts.

## Documentation

- [Quickstart](docs/quickstart.md): a disposable setup and first commands.
- [Operating the service](docs/operations.md): authentication, hosts, policy,
  credential rotation, approvals, and recovery.
- [Design](docs/design.md): intent, trust boundaries, and architectural decisions.
- [Dependency security](docs/dependency-security.md): advisory assessment and RSA compatibility.
- [Contributing](CONTRIBUTING.md): development checks, pull requests, and image publication.
- [Outbound connections](docs/outbound-connections.md): HTTPS and certificate trust.
- [Security reports](SECURITY.md): how to request a private reporting channel.
- [Preparing a public release](docs/releases.md): snapshot and distribution checks.

Use GitHub issues for reproducible bugs and feature requests. Include the
revision, relevant configuration **names**, and a minimal example. Remove
credentials and private deployment details from reports.

## License

[MIT](LICENSE).
