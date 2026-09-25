# Operating the service

The initial supported setup is one administrative domain using Linux containers
and POSIX-shell SSH targets. Start with the [disposable tutorial](quickstart.md).
Review the [design preconditions](design.md#non-goals-and-preconditions) before attaching real
hosts. Multiple independent tenants, multiple active replicas, and OAuth login
are outside the initial supported setup.

## Transport and output destinations

`MCP_SSH_TRANSPORT=http` (the default) serves stateless MCP Streamable HTTP.
Expose HTTPS through an operator-managed TLS proxy with a protected connection
to the service. The service's listener itself speaks HTTP; it does not issue or
manage certificates. No gateway is required for this standalone deployment.

`MCP_SSH_TRANSPORT=stdio` uses newline-delimited MCP on stdin and stdout. The
launcher grants account access and owns the process; `MCP_SSH_PRINCIPAL` provides
its audit identity and defaults to `local`. Do not configure an MCP bearer or
gateway identity mode for stdio. Tool arguments cannot change this identity.
The process exits when its input closes, after bounded outcome recording.

Select outputs independently:

| Variable | Values and default |
| --- | --- |
| `MCP_SSH_AUDIT_SINK` | `stdout`, `stderr`, or `file:<path>`. HTTP defaults to stdout; stdio requires an explicit file. |
| `MCP_SSH_LOG_SINK` | `stdout`, `stderr`, or `file:<path>`. Defaults to stderr. Stdio refuses stdout. |

The service rejects shared audit and diagnostic destinations, including file
aliases, and opens required outputs before accepting requests. Files append;
new files use private permissions on Unix. The operator owns directory creation,
rotation, storage capacity, and retention. A successful flush is not a disk
synchronization or collector acknowledgement. `RUST_LOG` affects diagnostics
only. Keep destinations separate when redirecting process file descriptors too.

Stdio does not open an HTTP listener unless an operator surface, evaluator,
or HTTP file origin is configured. Optional human review uses the same separately authenticated
HTTP operator surface; configure its reachable dashboard URL and TLS proxy
when remote access is needed. `--healthcheck` is for deployments with an HTTP
listener, not a stdio-only process.

## File transfer

Configure `MCP_SSH_FILE_ORIGIN` for the HTTP byte channel, or
`MCP_SSH_FILE_ROOT` for local stdio file references.
Set `MCP_SSH_MAX_TRANSFER_BYTES` to override the 2,000,000,000-byte default.
For network transfers, `MCP_SSH_FILE_STAGING` selects writable disk-backed staging
storage; local mode uses the shared root. `MCP_SSH_TRANSFER_TIMEOUT_SECONDS`
sets the transfer deadline (default 1800 seconds). See
[file transfers](file-transfers.md) for tool arguments, gateway integration,
storage bounds, and interrupted-write recovery.

## Choose authentication explicitly

Standalone authentication is the default for HTTP. Set
`MCP_SSH_AUTH_MODE=standalone` explicitly if desired. Supply:

| Variable | Meaning |
| --- | --- |
| `MCP_SSH_BEARER` | A generated MCP token of at least 32 visible ASCII bytes. |
| `MCP_SSH_PRINCIPAL` | The fixed MCP identity; defaults to `local`. |
| `MCP_SSH_OPERATOR_PASSWORD` | Optional operator surface: a different generated password, 32–1024 visible ASCII bytes. Required when local review is enabled. |
| `MCP_SSH_OPERATOR_NAME` | Browser login name and approval identity; defaults to `operator`. |
| `MCP_SSH_DASHBOARD_URL` | The approval page URL clients should present to the operator. Required when local review is enabled. |

Names are labels, not secrets. Do not use a credential value as an identity.
The service rejects a name equal to either configured standalone credential.
The dashboard uses HTTP Basic authentication; publish plain HTTP only through
loopback for a local setup. Use authenticated TLS termination for remote access,
with a protected hop to the service. Restrict access to container environments
and the host's Docker socket because they expose deployment credentials.

`MCP_SSH_AUTH_MODE=gateway` explicitly enables signed gateway identity. It requires
`MCP_SSH_GATEWAY_BEARER_CURRENT`, `MCP_SSH_IDENTITY_JWKS_URL`, and
`MCP_SSH_IDENTITY_ISSUER`. Configure `MCP_SSH_PROXY_BEARER_CURRENT` only when
using the separately authenticated operator surface. The gateway supplies
an EdDSA-signed `x-mcp-identity` assertion for audience `mcp-ssh-rs` and its
service bearer. The authenticated dashboard proxy supplies its separate bearer
and the operator identity header configured by `MCP_SSH_OPERATOR_HEADER`
(default `x-mcp-operator`), stripping caller-supplied identity headers first.
Optional `MCP_SSH_GATEWAY_BEARER_PREVIOUS` and
`MCP_SSH_PROXY_BEARER_PREVIOUS` support a rotation overlap. Gateway and
standalone settings cannot be mixed. A failed gateway never enables standalone
authentication.

The authenticated MCP control route accepts request bodies up to 256 KiB,
allows ten seconds to read a body, and admits at most 64 requests concurrently.
It returns HTTP 413 for excess bytes, 408 for a body-read timeout, 400 for a
body transport error, or 503 when request capacity is occupied. Capacity is
released on completion or cancellation. These limits apply before JSON decoding
and are fixed service defaults. They do not limit command runtime or the
separate streaming file-byte routes; see [file transfer limits](file-transfers.md#limits-and-outcomes).

## Add a host

Set `MCP_SSH_REGISTRY` to a JSON file. The tutorial generates a working example
in `.quickstart/registry.json`. Each host names its SSH address, pinned public
host key, and roles. A role names a target account and a credential reference.

```json
{
  "example": {
    "address": "host.example:22",
    "host_key": "<verified OpenSSH public host key>",
    "roles": {
      "readonly": {"user": "mcp-read", "credential": "example-read", "access_class": "read_only"}
    }
  }
}
```

Replace the address, key, and account with your configuration. Obtain the host
key through an authenticated administrative channel; an unauthenticated
`ssh-keyscan` result alone does not establish who owns the key. A changed pin
causes connection refusal until you verify and configure the replacement.

Inject the role's unencrypted OpenSSH private key as
`MCP_SSH_CREDENTIAL_EXAMPLE_READ`. References are uppercased and non-alphanumeric
characters become underscores after the `MCP_SSH_CREDENTIAL_` prefix. References
that collide after this conversion are refused at startup. See
[RSA compatibility](dependency-security.md#rsa-compatibility) if using RSA.

Create target accounts and their permissions separately. Give each role only
the target permissions it needs, and verify a privileged operation fails under
the restricted account. A role named `readonly` does not configure the target
account or prevent writes by itself. Do not grant Docker-socket or unrestricted
sudo access to a role intended for diagnosis.

Set every account's `access_class` to `read_only` or `privileged`; the service
rejects missing or unrecognized classes. Discovery returns that configured class.
Include `host`, `role`, and `access_class` when opening, executing, polling, or
closing a session. The arguments must match the configured account and the
session; they let an upstream gateway make an account-access decision.

## Local review and configuration changes

Set `MCP_SSH_REVIEW` to `disabled` (the default), `all`, or `privileged`.
The setting controls local human review for configured accounts. Privileged
review holds every command on an account marked privileged; it does not inspect
command text. An upstream gateway separately decides account entitlement.
Neither local approval nor an agent's requested class grants target permissions.

Registry, review, credentials, and bearer configuration are read at startup.
Restart after changing them. Restart loses active sessions, runs, and pending
approvals; it does not undo commands already sent to a target. For standalone
credential rotation, stop new requests, restart with new credentials, and
update the corresponding client or browser login. Keep MCP and operator
credentials separate throughout rotation.

`MCP_SSH_LISTEN` defaults to `0.0.0.0:8080` inside the container. Limit the host
port publication explicitly, as the tutorial does. `MCP_SSH_TRUSTED_HOSTS` adds
configured authorities to the MCP transport's loopback Host allowlist. Do not
turn that guard off to resolve a proxy configuration problem. `/healthz` is
liveness only; it does not establish usable credentials, a reachable SSH
target, or available gateway signing keys.

## Approvals and recovery

Use a session purpose that tells the operator what work is intended. A held
command returns an approval URL if configured. Review the actual arguments and
target before approving. After approval, resubmit that held command once to
collect the decision. If execution is still running, use `ssh_poll` with the
returned run identifier. A completed poll result is consumed, so retain it.

If a connection ends with an unknown execution outcome, inspect the target or
ask its administrator before repeating a consequential operation. An expired
or restarted session needs a new session; an approval does not survive restart.
Default sessions have a day-long maximum and idle limit, with a short grace
period. Pending human decisions expire after an hour. These limits currently
come from `settings::bounds`; they are not environment settings.

## Logs and optional integrations

Collect the configured JSON audit destination with appropriate access control
and retention. Command arguments, identity labels, and output
can contain sensitive operational data. The process-local chain is not durable
storage or a restart-spanning history. See the [recording design](design.md#audit-and-evaluation).

Configure `MCP_SSH_AUDIT_QUERY_URL` and `MCP_SSH_AUDIT_LABELS` together to enable
Loki history. Labels are an explicit JSON object, such as
`{"app":"ssh-service","stream":"audit"}`, matching the deployment's collector.
Without the pair, historical pages report the durable source unavailable.
Authenticated remote Loki access requires a separately protected adapter.
`MCP_SSH_NOTIFY_URL`, together with `MCP_SSH_DASHBOARD_URL`, enables an optional
approval-notification webhook. Neither integration is required for the tutorial.
These outbound integrations and gateway key discovery support verified HTTPS
as well as protected internal HTTP. See [outbound connections](outbound-connections.md)
for certificate trust and private CA configuration.

An optional evaluator may append advisory evidence using
`MCP_SSH_EVALUATOR_BEARER_CURRENT` and `MCP_SSH_EVALUATOR_NAME`, with an optional
previous bearer for rotation. It cannot execute or approve commands. Its
credentials must be distinct from both MCP and operator credentials.
