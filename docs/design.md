# mcp-ssh-rs — design

An MCP service that gives AI agents constrained, audited, on-demand SSH access
to homelab hosts, with policy-based authorization and human-in-the-loop
approval for what policy flags.

**What this document is.** Intent, trust boundaries, component
responsibilities, and the decisions that would be expensive to reverse. It is
deliberately *not* a specification of tool signatures, schemas, policy syntax,
storage layout, or wire formats. Those are implementation: they belong in code
and tests, where they can be validated, and where changing them does not
require editing prose. Where this document and the code disagree about a
mechanism, the code is right and this document should be corrected or made
less specific.

The product survey, standards review, and code-level evaluations that informed
these decisions are kept outside the repository. They are evidence for how the
decisions were reached, not guidance for building, and nothing here depends on
them.

---

## 1. Non-goals — read this first

The boundary matters more than the feature list, and it is the thing most
likely to be eroded by well-meaning changes.

1. **Not a human bastion.** Humans keep their existing SSH access. Serving
   human interactive access would pull in terminal UX, protocol breadth, and a
   different threat model. If a mediated human path is wanted, deploy a
   purpose-built bastion separately, uncoupled from this service.
2. **Classification is not containment.** Command classification — static or
   assisted — is advisory input to policy and can be wrong. The containment
   boundary is the **role credential**, enforced remotely by the target's own
   `sshd` and `sudoers`. A classification defect must be an audit gap, never a
   privilege escalation. Design and review accordingly.
3. **Does not provision credentials or target accounts.** The service is given
   credential sets and selects among them. It does not create accounts, manage
   `sudoers`, or rotate keys.
4. **Not a secrets store.** Secret values are referenced, not held.
5. **Does not replace the deployment process.** Work that belongs in version
   control and a deployment pipeline must not be smuggled through an agent SSH
   session.
6. **SSH only.** No RDP, VNC, database, or Kubernetes targets.
7. **No port forwarding or tunneling.** It is recording-opaque and would make
   the service an arbitrary network pivot — the capability being removed from
   agent sandboxes.
8. **Not a fleet orchestrator.** One host per session; no fanout, inventory,
   or configuration management.
9. **No target-side agent daemon.** Plain `sshd` is the contract.
10. **It cannot enforce its own necessity.** An agent that already has raw SSH
    egress will route around the service.

### Preconditions

These are properties of the environment, not deliverables of this service, and
the design is unsound without them:

- Agent sandboxes cannot reach port 22 except through this service.
- **Authentication mode is explicit.** Gateway deployments admit MCP through
  the gateway's bearer and signed principal assertion, and the dashboard
  through a separately authenticated reverse proxy. Network policy must not
  provide a bypass around those peers. Personal standalone deployments admit
  an MCP bearer as one configured principal and authenticate the human
  separately. Clients sharing the MCP credential share that identity, session
  ownership, and quotas. Neither mode isolates independent administrative
  tenants. Credentials for MCP, human approval, and optional evaluation must
  remain separate. Plain HTTP standalone access is limited to a local setup;
  remote credential-bearing connections require protected transport.
- Roles are provisioned with different privilege on the target, demonstrated by
  an operation that succeeds under one and is refused under another. If every
  role is effectively root, role separation buys nothing and non-goal 2 has no
  boundary to fall back on.
- Host identity is verified against pinned material rather than trusted on
  first use.

---

## 2. Use cases

Demand is overwhelmingly read-only diagnosis that agents cannot do at all
today, where a human currently SSHes in and relays output.

- **Diagnose an unhealthy stack.** Inspect containers, logs, and unit state;
  correlate with existing observability. Many commands, no human interaction.
- **Explain why a deploy did not take effect.** Compare on-host files against
  the repository, check mounts and restart times. The most common debugging
  loop here, and currently the most human-relayed.
- **Act on a diagnosis** — create directories for a new service, restart a
  unit, reclaim disk. Mutating, and gated accordingly.
- **Work on the remote family site**, where existing policy already requires
  human confirmation for anything host-level.

Anti-use-cases, and what actually holds each one. Destructive primitives and
unapproved privileged changes are held by policy, which decides on facts
classification produces: the program, its subcommand, and how much either could
do. Reading credential or key material is held by the role account itself - the
target refuses what that account cannot read - and, where a path is stated
rather than buried in a command line, by policy on that path. Naming the reader
is not a mechanism: `cat`, `tar` and an interpreter read the same file, and
which word of a command is a path is a question about the option that carried
it. Non-goal 2 is the general form of this: classification is not containment.

---

## 3. Trust boundaries and invariants

Properties the system must hold. They are stated here because violating one
means the design failed, not because this document defines how they are
enforced — tests own that.

1. **The agent never holds an SSH credential or an SSH endpoint.** It names a host
   and at most a role.
2. **Every execution is attributable and pre-recorded.** A complete audit entry
   is written and flushed to the service's standard output before a command
   runs; if that write fails, the command does not run. This is the selected
   recording boundary: the fleet log pipeline owns collection, storage, and
   retention after stdout. The service does not claim collector acknowledgement
   or service-owned durability, and its in-process chain does not survive a
   restart.
3. **Every execution belongs to exactly one session, bound to the principal it
   was opened for, one host, and one role.** There is no session-less path, and
   a session is usable only by that principal — otherwise one authenticated
   caller could drive another's session, or spend an approval granted to them.
4. **Authorization is per command**, evaluated against the principal, the host,
   the role, the command's classification, and its arguments — not granted once
   per connection.
5. **Facts and decisions are separated.** Classification produces facts; one
   policy engine decides. Nothing else may authorize.
6. **A caller cannot assert its own authorization inputs.** Claims an agent
   makes about its own command may raise suspicion; they may never widen
   access.
7. **Approval authorizes an action, not a capability.** An approved request
   causes the service to act; it never yields something the agent retains.
8. **Approval narrows nothing into existence.** It can lift a specific
   restriction; it cannot substitute for permission that was never granted.
9. **Unavailable assistance is fail-closed.** An advisory component failing,
   timing out, or being absent never yields more access than its absence
   would.
10. **Refinement is bounded, and cannot rescue the unidentified.** Assistance
    may refine the assessment of a command that was *identified*, and only
    where policy permits refinement for that target and the role credential
    contains the refined outcome. A command that could not be identified at
    all keeps its maximal assessment: no amount of assistance lowers it, and
    only a human's explicit approval — never a refinement — lets it run.

---

## 4. Architecture

Five responsibilities, deliberately separated so that the failure of any one
degrades safely.

**Front doors.** The MCP route supports a gateway integration and an explicit
personal standalone mode. Gateway mode authenticates a shared bearer and a
signed principal assertion. Standalone mode maps a separate configured bearer
to a fixed principal; a missing assertion or unavailable gateway never enables
this mode implicitly. Both modes use the same session and command authorization.
The human dashboard uses either an authenticated proxy identity or a separate
standalone operator login. An operator administers the configured service as a
whole; per-team approval isolation is not promised. The optional evaluator
ingestion route has its own credential and no authority to execute or approve.
Only the liveness probe is unauthenticated, and it reveals no inventory or
policy state.

**Session.** The unit of work, audit, and approval: one host, one role, a
declared purpose, a scope ceiling, and a bounded lifetime. The session exists
because disconnected command records are individually precise and collectively
useless — intent cannot be reconstructed from them — and because approving a
declared piece of work is the only way to keep human involvement meaningful
rather than reflexive.

A session's lifetime is its own and is not the SSH connection's. A target that
restarts ends the transport underneath without ending the session, and so does
a network that drops it or a target that stops answering; in each case the
connection is established again beneath a session that is still live. A session
sitting idle is not one of those cases: an idle connection asks its target
whether it is still there, so a pause between commands — waiting for a human to
approve one, most of all — does not cost a reconnection. Only the session's own
expiry — idle or maximum — or its owner closing it ends the work.
Reconnecting is not a second way to authorize anything: it reaches the same
host and role through the same registry entry, with the same pinned host key
and the same credential, and every command that then runs is authorized
individually exactly as it would have been on the first connection. It happens
only between commands, never around one already in flight, so a transport lost
mid-command stays a failure the caller is told about rather than a command
quietly run twice.

**Execution.** A single execution path takes a command as an argument vector
and runs it on the session's host. Argument vectors give unambiguous
identification of what is being run and let the service control quoting at the
wire boundary; they do **not** restrict what can be expressed, which is why
classification exists. Execution that outlives its caller's patience remains
addressable rather than being lost.

Every execution also carries a bounded, non-blank explanation of what that
command is meant to accomplish. This is **agent-supplied command intent**:
useful evidence for a reviewer and for advisory evaluation, but not a trusted
user's instruction and never a basis for expanding authorization. It is
recorded before execution and shown under that provenance label. A one-command
approval is bound to the exact argument vector and the exact agent explanation,
so an agent cannot collect an answer while changing its story. The session
purpose
is separate, broader context; neither value is allowed to impersonate
authenticated identity or a future gateway-supplied user-intent claim.

**Classification.** Turns a command into facts: what it is and how much it
could do. Deliberately not *what it touches*: which part of an argument names a
file is a question about the option that carried it, the answer is not in the
command's text, and a mechanism that guesses reports files nobody named and
misses ones somebody did. What a command touched is observable where it is
actually knowable - in the record of what ran, and on the target. Two producers,
layered by cost:

- A catalog covering the known vocabulary, applied first and cheaply. It
  answers *what program is this*. A command it cannot identify is never
  assumed benign: it carries the maximal assessment with the reason on
  record, so the shipped policy puts it in front of a human rather than
  running it, and a session whose ceiling does not reach that assessment
  refuses it outright. Evidence may raise an assessment but never lower
  it. The vocabulary may declare, per program, that options it does not
  list carry a stated scope — a statement about a known program none of whose
  flags exceed that scope (its exceptions being described individually), so
  that harmless spellings need not each be written down. That declaration is
  refused wherever an unread option could change which word carries the
  command's effect: on interpreters and subcommand programs.
- An optional assisted stage, which answers a different question: *given that
  we know what program this is, what will this particular invocation actually
  do*. It applies only to commands the catalog identified. The case that
  matters is a program correctly identified and treated as maximally
  privileged because of what it *could* do — an interpreter, typically — where
  the payload it was handed is the real unknown. Resolving that is what keeps
  interpreted work from permanently requiring a human. The stage also compares
  what a command does against what it was said to be for; divergence is
  signal.

  It may therefore lower an assessment, bounded by invariant 10, and it is
  safe to be wrong only because the role credential contains the outcome
  (non-goal 2). It can never lower an unidentified command's assessment:
  whether such a command runs is a human's answer, and assistance does not
  stand in for one.

**Decision and record.** One policy engine authorizes each command from those
facts. Everything it decides, and the facts it decided from, joins a
tamper-evident, session-scoped in-process transcript and is also written through
the required recording boundary before an authorized effect begins. The fleet
log pipeline owns collection, storage, retention, and queryability beyond
stdout; this service neither waits for collector acknowledgement nor preserves
its transcript across a restart. The structured records the pipeline collects
are the product for most use cases, which is why execution is preferred over
terminal capture wherever a choice exists.

### Data leaving the service

Two distinct classes, conflated at everyone's peril:

- **Service-held credentials** never leave, in any form, anywhere.
- **Secret-shaped bytes appearing in target output** are a different class:
  the agent is an authorized reader at its role's privilege. Residue that is
  *recognized* is withheld from the response and published through the
  gateway's out-of-band file channel instead, so it stays retrievable by an
  authorized non-model consumer. The
  agent is told what was withheld rather than being handed quietly altered
  output, because silently mangled output would make deploy verification
  unreliable.

  **Recognition is incomplete and always will be.** Detecting a secret in
  arbitrary command output is a heuristic, so this withholds what it matches
  and nothing more — it is not a guarantee that secrets never reach model
  context. Treating it as one would set later implementation and review against
  a target nothing can hit. What actually bounds the exposure is the role
  credential: it limits what the agent can read at all.

  A path is enforceable where a path is *stated* rather than inferred. The file
  operations take one as a typed argument, so policy can bind to it and refuse
  a credential path there exactly. It is not enforceable against a command
  line, where which word is a path is a question about the option that carried
  it - see Classification above.

Bulk data — large output, file transfer, and secret placement — moves through
that same channel as references rather than bytes. The service implements the
upstream side of the fleet's existing file-transfer mechanism rather than
inventing one.

---

## 5. Approval

Approval is a recorded decision that a second party can verify, not a message
someone answered. The dashboard holds approval state and is the surface where
decisions are made; notification channels are optional pointers to it and are
never themselves the channel of record.

What a human sees must be sufficient to decide well: the host, the role, the
declared session purpose, explicitly agent-supplied command intent, the exact
action, and the available authenticated identity context. The service must not
invent a human-via-agent chain from a gateway principal that does not contain
one; separately authenticated delegation claims can be added and recorded when
the gateway supplies them. Grants are bounded in time and in what they permit,
and a grant for one action or stated intent cannot be redeemed for another.
Requesting and approving are structurally different identities even with a
single operator, because the agent requests and the human approves.

An operator may also let their answer stand for one session. A standing
session agreement is given on the dashboard, in response to a request they can
see; from then until it expires, is withdrawn, or the session ends, each held
command in that session is answered in their name without asking again. This
does not weaken invariant 7: the agent is handed nothing and retains nothing —
every command is still individually decided, recorded, and run under a
single-use, single-command grant. What stands is the human's answer, held by
the service. The agreement is bounded by the session's own maximum lifetime
whatever the grantor chooses, it lifts nothing policy refuses outright or the
ceiling denies, and each answer it gives is recorded as the standing
agreement's — distinguishably from a decision clicked for one command, the
same way an override is distinguishable from an approval.

The session-wide agreement remains an explicit operational safety valve while
the review process matures. An operator may instead choose a narrower
**matching-work agreement**. Its first version is deterministic: the same live
session (and therefore principal, host, role, purpose, and ceiling), the same
catalog version, an identified non-interpreter program/subcommand family, and
an assessment no higher than the command the operator reviewed. It cannot
answer a policy denial, cross sessions, rescue an unidentified command, cover
an interpreter, or use an LLM judgement as authorization. Each automatically
answered command still records its own agent-supplied intent.

Command operands are still shown and recorded exactly, but the catalog does
not know which operands name resources. The first matcher therefore says
plainly that operands may vary and does not claim a resource selector. A later
selector belongs here only when a typed command or catalog rule can derive it
deterministically. Every automatic answer records whether it came from a
matching or session-wide agreement, the individually revocable agreement ID,
and, for matching work, the matcher version. A matching agreement is tried
before a coexisting session-wide agreement so the audit keeps the narrowest
provenance that actually answered.

Agreement use is linearized with expiry and withdrawal. If expiry or
withdrawal wins first, the held command remains waiting. If use wins first,
selection, answer recording, and redemption into an exact single-command grant
finish before withdrawal can return; withdrawal then governs later held
commands and does not rewrite an answer already recorded. There is no interval
in which a removed or expired agreement can still be cloned into a new answer.

A break-glass path exists for outages: bounded, single-use, expiring, requiring
a stated reason, and conspicuous in the record.

### Operations and advisory evaluation

The authenticated dashboard is a hybrid operations workspace. Its review queue
remains the default and the only dashboard view that changes authorization.
Inventory exposes the hosts and role boundaries in the loaded registry without
claiming that listing one grants permission. Sessions expose current lifecycle
state without refreshing idle time; their durable drill-down joins decisions,
human answers and authorization, observed outcomes, and advisory evaluations by
recorded sequence or digest rather than by timing. The audit view provides
bounded time-window, recorded assessment and verdict, principal, session, host,
event, and free-text search. All agent- and evaluator-written text is rendered
as untrusted input, including controls that could otherwise reorder or hide
what an operator sees.

The evaluation view provides the same closed time-window and decision-
assessment choices plus advisory verdict filtering. An evaluated entry repeats
the bounded argument vector, agent intent, session purpose, and assessment from
the exact decision it names, making that filtered evidence self-contained
without another source query. These repeated facts remain evidence only and
are never read by authorization.

Current session lifecycle state is explicitly process-local and says “since
restart.” Audit and evaluation history is read through an optional, fallible,
read-only adapter to the deployment's existing fleet log record. The service
does not create a second durable copy. When that source is absent or fails, the
dashboard reports it unavailable rather than substituting the in-process chain
or a stale successful page.

Durable reads are cursor-paginated, serialize their potentially large source
queries, and bound both entries and response bytes. Structured filters are
applied by the source so a session can be followed beyond the newest global
page. A session transcript pages by command decisions and resolves their
answers, authorization, outcomes, and evaluations across the raw source pages
by recorded identifiers; evidence the durable source does not contain remains
explicitly absent rather than guessed from timing. Decisions, rather than
approval entries, select the command page: policy-permitted executions and
human-released executions therefore follow the same transaction path, while a
denied decision is shown without inventing a completion. Each result carries the
collector's wall-clock timestamp and the audit
entry's own sequence and digest; the UI does not call source availability or
the presence of those fields a complete chain verification. Completed entries
include searchable stdout and stderr evidence. Transaction cards render at
most a 2 KiB preview per stream; a kept stream links to an on-demand read for
the exact typed session and run within the transaction page's fixed source
window. That detail view renders the complete retained stream, up to the
execution path's existing capture bound, and states when the target produced
more. Secret-shaped output remains withheld and is shown only as a typed
omission. The detail path is authenticated and read-only and creates no second
output store.

An optional evaluator is a fourth, separately authenticated participant. It
may append one bounded, immutable artifact per exact readable command decision
digest, naming its model and prompt version, confidence, rationale, and possible
side effects. The dashboard shows when that artifact entered the audit chain as
well as its evaluator and model provenance. Its identity is deployment-owned
rather than accepted from request content. Evaluation identifiers are
idempotent: an exact retry returns the same evidence while its entry is
readable. Neither an issued identifier nor an evaluated decision digest is
reusable, including after retention seals the entry's content.

Evaluation is evidence only. No verdict authorizes a command, lowers an
assessment, widens a matching-work agreement, changes an earlier decision, or
mints an execution receipt. Until the gateway supplies a separately
authenticated user-intent claim, evaluators compare only against the explicitly
labeled agent-supplied command intent and the broader session purpose; neither
is presented as trusted human intent.

---

## 6. Material tradeoffs

- **Per-command authorization over per-session.** Costs a decision on every
  command; buys the ability to refuse one command without ending the work, and
  audit that answers questions rather than requiring replay. A standing
  session agreement does not reverse this: it changes who answers a held
  command's question, never whether each command is asked.
- **Sessions are mandatory even for one-off commands.** Costs a round trip;
  buys a purpose on every record and a coherent approval unit. The pooled
  connection makes everything after the first command faster.
- **Assisted classification may lower an assessment.** Costs a dependency that
  can be wrong and can be adversarially influenced; buys ordinary interpreted
  work without constant human involvement. Acceptable only under invariant 9
  and non-goal 2.
- **Two policy surfaces** (gateway and service). Costs duplicated maintenance;
  buys enforcement for a caller the gateway cannot characterize.

---

## 7. Delivery order

Sequenced so the highest-value capability lands first and later decisions are
made on evidence rather than instinct.

1. **Preconditions.** Roles, pinned host identity, egress denial.
2. **Read-only execution.** Sessions and command execution, with policy
   **enforcing from the first command that ever runs** and an initial policy
   deliberately narrow enough to permit only read-class work.

   There is no phase in which commands execute while the decision point merely
   observes. Observe-then-enforce is a technique for retrofitting policy onto
   traffic that already exists and must not be broken; here there is no such
   traffic, so it would only mean something other than the policy engine was
   authorizing — which invariants 4 and 5 forbid. Observation is still
   valuable, but for *widening*: the useful signal is what agents asked for and
   were refused, which enforcement produces and permissiveness hides.

   This milestone delivers the two highest-volume use cases and produces the
   evidence the remaining design questions need.
3. **Mutation and approval.** Higher-privilege roles, the approval path, the
   dashboard, file operations.
4. **Assisted classification.**

Interactive terminals are deliberately absent from this plan. They are wanted,
but they cannot satisfy invariants 4 and 7: a terminal carries a byte stream
rather than identifiable commands, so authorization cannot be per command, and
an approved session is a retained capability rather than a single action.
Whether to hold the invariants and drop terminals, or state a bounded exception
for them, is a real decision that should be made against working code rather
than settled here in advance.
5. **Optional hardening.** Moving authorization enforcement onto the target
   itself, and removing the shell from the execution path.

---

## 8. Rejected and deferred

Recorded so they are not silently revisited. Each was reached by evaluating the
alternative rather than by assumption; the evaluations themselves are kept
outside the repository.

**Delegating sessions to an external bastion (rejected).** It would hand the
agent a usable credential and an SSH destination, require restoring the port-22
egress this service exists to remove, and move session I/O outside the audit
envelope. It would also need its own target and credential registry, creating a
second source of truth, and its records identify a ticket rather than the
human-plus-agent chain.

**Terminal capture as the primary record (rejected).** A byte stream cannot be
reliably decomposed into what commands ran; the tools that try document
themselves as audit aids rather than boundaries.

**Optional sessions, and separate synchronous/asynchronous execution paths
(rejected).** The first produced records with no host and no purpose. The
second forced agents to predict whether a command would be slow, which they
cannot do, and duplicated the authorization and audit paths.

**Typed per-operation tools (deferred).** Narrow tools for common operations
would sidestep classification entirely for the traffic that matters, but we do
not yet know the traffic. Step 2 produces that evidence, and such tools remain
purely additive.

**Adopting an existing gateway product (rejected).** The one with the closest
feature match does not ship its mediation engine as open source, and its
policy model is weaker than the one this design depends on.

---

## 9. Open questions

- Model choice and hosting for assisted classification.
- Whether a fixed role vocabulary is adequate or roles should be per-host.
- Whether CI eventually routes through this service or keeps its own keys.
