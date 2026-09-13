# Operating the service

The initial supported setup is one administrative domain using Linux containers
and POSIX-shell SSH targets. Start with the [disposable tutorial](quickstart.md).
Review the [design preconditions](design.md#preconditions) before attaching real
hosts. Multiple independent tenants, multiple active replicas, OAuth login,
and file-transfer integration are outside the initial supported setup.

## Choose authentication explicitly

Set `MCP_SSH_AUTH_MODE=standalone` for a personal deployment. Supply:

| Variable | Meaning |
| --- | --- |
| `MCP_SSH_BEARER` | A generated MCP token of at least 32 visible ASCII bytes. |
| `MCP_SSH_PRINCIPAL` | The fixed MCP identity; defaults to `local`. |
| `MCP_SSH_OPERATOR_PASSWORD` | A different generated password, 32–1024 visible ASCII bytes. |
| `MCP_SSH_OPERATOR_NAME` | Browser login name and approval identity; defaults to `operator`. |
| `MCP_SSH_DASHBOARD_URL` | The approval page URL clients should present to the operator. |

Names are labels, not secrets. Do not use a credential value as an identity.
The service rejects a name equal to either configured standalone credential.
The dashboard uses HTTP Basic authentication; publish plain HTTP only through
loopback for a local setup. Use authenticated TLS termination for remote access,
with a protected hop to the service. Restrict access to container environments
and the host's Docker socket because they expose deployment credentials.

`MCP_SSH_AUTH_MODE=gateway` retains the existing integration and is the default
when the mode variable is absent. It requires
`MCP_SSH_GATEWAY_BEARER_CURRENT`, `MCP_SSH_PROXY_BEARER_CURRENT`,
`MCP_SSH_IDENTITY_JWKS_URL`, and `MCP_SSH_IDENTITY_ISSUER`. The gateway supplies
an EdDSA-signed `x-mcp-identity` assertion for audience `mcp-ssh-rs` and its
service bearer. The authenticated dashboard proxy supplies its separate bearer
and `x-authentik-username`, stripping caller-supplied identity headers first.
Optional `MCP_SSH_GATEWAY_BEARER_PREVIOUS` and
`MCP_SSH_PROXY_BEARER_PREVIOUS` support a rotation overlap. Gateway and
standalone settings cannot be mixed. A failed gateway never enables standalone
authentication.

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

## Policy and configuration changes

The shipped policy permits catalog-classified reads within the session's scope
and holds consequential commands for approval. Use `MCP_SSH_POLICY_PATH` for a
replacement Cedar policy. The service retains its built-in scope ceiling rules.
Test your policy with allowed, denied, and held commands on disposable targets
before using it on real hosts. Catalog extension configuration is not yet part
of this setup.

Registry, policy, credentials, and bearer configuration are read at startup.
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

Collect the service's JSON standard output into a log store with appropriate
access control and retention. Command arguments, identity labels, and output
can contain sensitive operational data. The process-local chain is not durable
storage or a restart-spanning history. See the [recording design](design.md#3-trust-boundaries-and-invariants).

`MCP_SSH_AUDIT_QUERY_URL` enables the existing Loki history reader. Without it,
historical dashboard pages explicitly report the durable source unavailable.
The current reader assumes the container label `mcp-ssh` and stdout stream;
adapting labels and authenticated remote Loki access remains deployment work.
`MCP_SSH_NOTIFY_URL`, together with `MCP_SSH_DASHBOARD_URL`, enables an optional
approval-notification webhook. Neither integration is required for the tutorial.
These outbound integrations and gateway key discovery support verified HTTPS
as well as protected internal HTTP. See [outbound connections](outbound-connections.md)
for certificate trust and private CA configuration.

An optional evaluator may append advisory evidence using
`MCP_SSH_EVALUATOR_BEARER_CURRENT` and `MCP_SSH_EVALUATOR_NAME`, with an optional
previous bearer for rotation. It cannot execute or approve commands. Its
credentials must be distinct from both MCP and operator credentials.
