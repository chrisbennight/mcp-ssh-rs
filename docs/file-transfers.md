# File transfers and command output

`ssh_download` reads a binary file from the SSH target and returns a file
reference. `ssh_upload` accepts a file URI and writes its bytes to the target
through SFTP. Neither tool accepts or returns inline file contents or base64.
The target must support SFTP as well as SSH.

Both tools require the session's `host`, `role`, and configured `access_class`,
plus `session`, an agent-supplied `intent`, and an absolute remote `path`.
Uploads also require `source` and an explicit `overwrite` boolean. With
`overwrite=false`, an existing target file causes failure. With `true`, the
existing file is truncated and replaced. Target account permissions still
control access; the service does not change ownership, modes, or confinement.

Optional human review applies by account, exactly as for commands. An upload
approval binds the destination, byte count, SHA-256 content digest, replacement
choice, and stated intent. A gateway may remap an unchanged upload to a new
private URI without invalidating that content identity. Changed bytes require
a new approval. A command cannot redeem a file-operation approval.

## HTTP byte channel

Set `MCP_SSH_FILE_ORIGIN` to the origin from which the client or gateway can
reach this service's byte routes, for example `https://ssh.example.org`.
The origin must have no credentials, path, query, or fragment. Configure the TLS
proxy to forward `/files/bytes/` as well as `/mcp`. The service does not fetch
arbitrary caller-supplied URLs.

The adapter uses the same upstream protocol as Waygate:

- `files/authorizeUpload` accepts optional name, media type, exact size, and
  SHA-256 digest and returns a `FileValue` plus an HTTP `PUT` descriptor.
- The client sends bytes using the descriptor's separate credential header.
  Uploads become available only after complete size and digest validation.
- The caller passes the returned URI as `ssh_upload.source`. Its network tool
  schema marks that string with `x-mcp-file` and upload-only transfer mode,
  and advertises the configured maximum transfer size.
- `files/authorizeDownload` resolves an owned reference to a `FileValue` and
  HTTP `GET` descriptor. The descriptor includes exact size and digest metadata.

Descriptors are for client or gateway runtime use; their credentials must not
be passed into model context. Each credential starts one byte transfer and
cannot authenticate MCP requests. A failed download can obtain a new credential
for the same immutable reference before it expires. References and authorization
requests are bound to the authenticated MCP principal. Byte routes authenticate
the separate transfer credential.

Waygate retains responsibility for its public file storage, grants, helper,
and policy. The SSH service implements the small upstream adapter. All returned
download authorizations carry the `secret` sensitivity hint so the gateway can
apply its shorter retention policy.

Stdio control can also use this HTTP byte channel: configuring the origin opens
the service's HTTP listener for byte routes. This supports an upstream whose MCP
control transport is stdio but whose gateway transfers bytes over HTTP(S).

## Local stdio references

For a stdio-only setup, set `MCP_SSH_FILE_ROOT` to an existing shared directory
instead of configuring a file origin. This option is accepted only with stdio
and cannot be combined with `MCP_SSH_FILE_ORIGIN`. File references refer to the
service's filesystem; a container launcher must mount the shared directory.

`ssh_upload.source` is then a `file://` URI inside that directory. Inputs must
be regular files. Descriptor-relative opens refuse symbolic links, including
links in parent directories, and snapshot the bounded bytes before review.
The launcher owns this local authority; tool arguments cannot select another
MCP principal.

Downloads and retained output are published as private files in a service-owned
subdirectory. Completed staging files are renamed into place without copying their
contents. Local staging uses the shared directory filesystem. The result carries
a `file://` URI that the launcher can open without sending its bytes through MCP. Publication exposes the final filename
only after the complete file has been written. Expiry and orderly shutdown
remove generated files; user input files are not removed. A forced process exit
can leave the private staging directory for operator cleanup.

Local mode has no HTTP file descriptors or upload annotation. A gateway needing
the network file protocol should use `MCP_SSH_FILE_ORIGIN` with its upstream.

## Metadata, listings, and checksums

`ssh_file_info` accepts `stat`, `list`, or `checksum` with the session account,
intent, and absolute remote path. It uses the same review and run workflow as
other file work and does not require a file byte channel. Results appear under
`info` when the run completes; poll a still-running operation.

A listing returns at most 128 entries within a 64 KiB result allowance and marks
an incomplete listing as `truncated`. It has no continuation cursor; inspect a
narrower directory when truncated. Recognized sensitive filenames are withheld.
Metadata includes the file type, optional byte size, permission bits, and
modification timestamp reported by the peer.

Checksums stream SHA-256 without publishing or returning file content. The
`MCP_SSH_CHECKSUM_MAX_BYTES` setting defaults to 64 MiB and the existing file
operation deadline also applies. A growing file is refused when the byte limit
is exceeded. Read-ahead is bounded by that limit plus one byte to detect an
oversized file. The digest describes the bytes observed during the read; concurrent
remote modification is not a filesystem snapshot.

## Staged replacement

For `ssh_upload`, supply `staging_path` and `overwrite: true` to request staged
replacement. The temporary path must differ from the destination and share its
directory. Both paths and the content identity are included in review. The
service checks for version 1 of
[OpenSSH POSIX rename](https://github.com/openssh/openssh-portable/blob/HEAD/PROTOCOL)
before creating the temporary file; an existing temporary path is refused.

A complete upload is closed before the rename request replaces the destination.
The new file requests mode 0600 and does not preserve the previous file's mode
or ownership. This provides the peer's POSIX rename visibility semantics, not
an fsync or crash-durability guarantee. Uploads without `staging_path` keep the
ordinary direct-write behavior.

Cancellation, a deadline, or connection loss can leave the named temporary
file. A lost rename acknowledgement, including cancellation or a deadline during
replacement, reports `replacement_unknown`: inspect both paths before retrying.
Local cancellation status remains available separately in progress.
Failed cleanup reports `staging_cleanup_failed`;
the service does not claim that removal succeeded. No mutation is replayed
automatically.

## Limits and outcomes

File contents stream through private disk snapshots with bounded application
buffers. Configure the maximum size with `MCP_SSH_MAX_TRANSFER_BYTES`, a positive
decimal byte count. The default is **2,000,000,000 bytes (2 GB)**. The same ceiling
applies to HTTP uploads, SFTP transfers, and local input snapshots. Invalid or
unsupported values prevent startup; size is enforced while reading even when a
sender omits its size. Command-output retention limits are unchanged.

Network staging uses `MCP_SSH_FILE_STAGING`, defaulting to the process temporary
directory (`TMPDIR`, or `/tmp`). Local mode stages inside the configured shared
root so publication can rename the completed file on the same filesystem. Mount
disk-backed writable storage for large transfers: a `tmpfs` or memory-backed container mount still consumes memory.

Storage reserves a full file allowance for each pending, receiving, or ready item,
with at most four items per principal and sixteen overall. At the default ceiling,
that is 8 GB per principal and 32 GB overall. Local input snapshots have a separate
limit of sixteen retained inputs, allowing another 32 GB in local mode. These are
logical admission limits, not preallocated physical space or a guarantee of free
disk space; disk-full errors fail the transfer. Filesystem overhead and other
processes' storage are outside these budgets.

Unstarted authorizations expire after five minutes. Once a transfer starts,
`MCP_SSH_TRANSFER_TIMEOUT_SECONDS` bounds HTTP upload, local input snapshot, and
SFTP operation duration. It defaults to 1800 seconds and accepts positive integers
up to 86400. Completed references receive a fresh five-minute delivery window.
Storage that has expired or been released remains charged while an active
service consumer still holds it. This includes local outputs being copied into
new input snapshots.

Transfer storage is a buffer for moving bytes, not an archive. A reference from
`files/authorizeUpload` is released as soon as an `ssh_upload` using it finishes
writing to the target, so its slot is free for the next upload. A successful
upload's result does not return its source. A reference whose upload fails,
times out, waits for approval, or is refused stays usable
until its window ends, so an investigated retry does not need the bytes sent
again. A released reference cannot be used again or downloaded; supply the file
again to place it on another target. Download and retained-output references
are not released by serving as an upload source. Instead, each is released once
an HTTP fetch has sent all of its bytes, so a gateway that copies a result's
file frees the slot for the next download. A fetch that fails or disconnects
early keeps the reference, so a new descriptor can retry it. Bytes a client
loses after all of them were sent cannot be fetched again. Fetch a reference
last if you also want to place it on another target. Local stdio outputs are
read from the shared directory rather than fetched, so they last until their
window ends. The trusted
stdio launcher controls the shared filesystem; files or descriptors it retains
independently are outside the service’s storage accounting. Operators
must also bound HTTP connection lifetime at their TLS proxy, including slow GET
consumers. Choose the operation timeout and proxy limits for the expected file
sizes and link speeds.

Network files and local input snapshots are unlinked immediately after opening
and disappear when their last descriptor closes, including process exit. Local
output staging files remain private until publication. Published local files are
removed on expiry and orderly shutdown; failed expiry cleanup is logged and keeps its reservation for another cleanup
attempt. After a forced exit, an operator may remove the private `.mcp-ssh-*`
output directory belonging to that stopped process. Do not remove another live
process's directory or user input files.

SFTP work uses the existing run tracker, survives a cancelled MCP call, and can
be polled with `ssh_poll`. Use `ssh_progress` for counters without collecting
the result, or `ssh_cancel` to request cancellation. Cancelled uploads may have
partial remote writes; inspect the outcome before retrying. File operations
have a bounded runtime. Failure or
interruption can leave a direct remote upload partial. Staged replacement
has the explicit behavior described above. An unknown result must be investigated before repeating an
upload. The service never automatically replays a mutation.

Downloads default to eight read chunks of up to 64 KiB in flight or awaiting
delivery, a 512 KiB read-ahead budget independent of file size. Set
`MCP_SSH_SFTP_READ_AHEAD` before startup to an integer from 1 through 64 to tune
that window. The maximum schedules up to 4 MiB per active download. Larger
windows can help higher-latency links and increase memory use; they do not
guarantee higher throughput. Invalid values prevent startup. Negotiated peer
limits can reduce chunk size. Responses are validated and delivered in offset
order, including short reads; a slow consumer stops further requests once that
window is occupied. Protocol framing and SSH have separate bounded buffers.
Direct uploads retain the dependency writer's acknowledgement pipelining.
Staged replacement uses bounded acknowledged writes before rename.
See [local performance measurements](performance.md) for repeatable scheduling,
backpressure, and polling fixtures.

Completed command output is returned inline only when it is small valid UTF-8
and not recognized as sensitive. Binary, sensitive, or larger output uses file
references. The retained stream bytes are preserved exactly; the result still
reports the total produced byte count and whether retention was truncated.
Recognition of sensitive material is incomplete and is not a security boundary.

Configure a byte channel before requesting bulk output. If the channel is
absent or storage capacity is exhausted, the result explicitly reports that
output is unavailable; it does not substitute a large text or base64 response.
Do not repeat a consequential command solely to recover unavailable output.
These references are temporary delivery, not durable artifact storage.

Transfer failures return `transfer_failed` with a bounded cause such as
`not_found`, `too_large`, `publication_unavailable`, or `worker_stopped` for an
unexpectedly terminated transfer worker. The same cause remains
available when polling. `remote_write_may_be_partial` distinguishes a failed
download from an upload whose target may already have changed; investigate
such writes before retrying. Raw storage and SFTP error text is not returned.
