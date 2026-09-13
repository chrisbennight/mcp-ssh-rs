# Design

An MCP service for audited SSH work on administrator-configured accounts.
Agents can diagnose problems and carry out authorized changes without holding
SSH credentials. The same execution core serves standalone deployments and
upstream gateways.

This document defines product intent, trust boundaries, and constraints.
Interfaces and storage formats are defined by code and tests.

## Non-goals and preconditions

The service does not provision target accounts, manage their permissions, rotate
SSH keys, or replace a deployment pipeline. It is not an interactive human
bastion or fleet orchestrator. It does not provide port forwarding, tunneling,
or protocols other than SSH. A session works with one configured host and
account; there is no arbitrary destination supplied by the caller.

Account permissions are enforced by the target operating system. An account
label does not configure or prove those permissions. Operators must verify the
restrictions they intend, including filesystem access, sudo, and access to
privileged sockets. The service cannot prevent an agent with independent SSH
credentials and network access from connecting outside it.

Operators supply verified host keys and protect the service's configuration,
credentials, audit destinations, and transport endpoints. Bearer credentials
sent over a network require TLS or an equivalently protected connection. A
standalone credential shared by clients gives them one identity and shared
session ownership and quotas; it does not isolate independent tenants.

## Account authorization

The administrator assigns each configured account an access class. Discovery
reports that class, and session operations expose the requested host, account,
and class so an upstream gateway can decide whether the caller may use them.
Those request arguments are claims to validate, never grants of authority.
The service checks them against its registry and the session binding before
performing the requested operation.

A privileged-session entitlement belongs to the upstream authorization system.
The SSH service exposes the facts needed for that decision and prevents a
caller from substituting a different account or claiming a less privileged
class. Standalone authentication authorizes use of the configured accounts;
requesting a privileged class is not an additional authentication factor.

Command text does not classify access. There is no shell allowlist, inferred
read-only operation, or command-content policy engine. A program, option, or
shell payload cannot change the session's account or its configured class.
Content-aware assessment, if provided by an evaluator, is separate evidence.

## Sessions and execution

Every execution belongs to a bounded session with an authenticated owner, one
host, one account, its configured access class, and an agent-supplied purpose.
The binding is immutable. Each operation checks ownership and session state;
a handle alone grants no access. Account configuration is fixed for the life
of the process, and a restart invalidates sessions and approvals.

Connections verify the configured host key and use the configured credential.
A lost connection may be established again for the same session between
commands. Reconnecting never changes accounts or replays a command whose
outcome is unknown. Results distinguish confirmed completion, refusal to start,
still-running work, and an unknown outcome.

Commands are argument vectors quoted for the target's POSIX shell. Quoting
preserves argument boundaries; it does not make a program or a shell payload
safe. Agents also provide bounded command intent, recorded as agent-supplied
evidence rather than trusted user authorization.

## Local human review

Local review is an optional deployment setting. It can cover all configured
accounts or only accounts marked privileged. When required, the operator sees
the exact command, agent intent, session purpose, target account, and available
authenticated identity before deciding. Agent authentication does not provide
operator approval authority.

An approval is exact, expiring, and single-use. It cannot authorize a different
command, changed intent, another session, or an account that was not granted.
The operator may explicitly let an answer stand for a bounded session. Session
agreements expire, can be revoked, and retain their provenance on every use.
Selection and use are serialized with withdrawal so a revoked agreement cannot
be used to mint another approval.

A command-family matcher is not a supported approval boundary. Optional
notifications point to the authenticated approval surface; they do not approve
work. Upstream and local review are independent: enabling both requires both,
and a local approval never overrides an upstream denial.

## Audit and evaluation

An execution must cross the required recording boundary before it begins.
Failure to write the required record prevents the effect. The record binds the
account and session, exact command and intent, local review decision, approval
provenance when applicable, and observed outcome. A failed outcome write does
not turn an operation that may have run into a safe retry.

The process-local transcript is bounded and tamper-evident within its lifetime.
It does not establish collector acknowledgement, restart-spanning durability,
or complete remote host activity. Audit collection and retention beyond the
configured sink are operator responsibilities. Diagnostic logging must not
suppress or substitute for required audit recording.

An optional evaluator may append bounded evidence tied to an exact recorded
decision. Evaluator identity is separate from agent and operator identity.
Its model, prompt version, confidence, rationale, and reported side effects
remain evidence: they cannot approve work, alter an account class, or mint an
execution receipt. Probabilistic analysis does not replace target permissions.
An absent optional evaluator does not prevent ordinary SSH work. A deployment
that requires blocking evaluation must define and enforce its failure behavior
before using that mode.

Historical audit readers are optional and read-only. Source failures and
missing evidence remain explicit; in-process state is not presented as durable
history. All agent- and evaluator-written text is untrusted when rendered.

## Data boundaries

Service-held SSH and integration credentials remain inside authorized runtime
boundaries and never enter MCP results or audit contents. Secret identifiers
and ordinary account metadata are distinct from credential values.

Target output is data the account can access. Recognized secret material is
withheld from model-visible output, but recognition is incomplete and is not a
containment guarantee. The account's actual permissions bound what can be read.
Bulk output, files, and secret placement belong in authorized reference-based
transfer paths rather than large MCP text or base64 bodies. Transfer references
must preserve ownership, bounds, expiry, cleanup, and truthful size and digest
metadata without exposing a reusable service credential.

Generic transports, review, audit, and transfer adapters belong in this
project. Host inventories, gateway entitlement policy, secret mappings,
notification destinations, and deployment-specific collection settings belong
in deployment configuration outside the public source distribution.
