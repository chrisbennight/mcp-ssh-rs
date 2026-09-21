# Install an identified release

Use a published [GitHub release](https://github.com/chrisbennight/mcp-ssh-rs/releases)
to select the source revision and tested container digest together. The initial
release is an early 0.1 release: interfaces and configuration may change, and
there is no long-term support commitment. See [Get help](../SUPPORT.md).

The published container is tested on Linux x86-64. Other architectures and
Docker Desktop on macOS or Windows have not been validated. There are no
standalone binary downloads or crates.io packages. Building from source remains
available through the [local demonstration](quickstart.md).

## Obtain and try the container

Install Docker with a local Linux daemon, Compose v2 or newer, Python 3.11 or
newer, OpenSSH's `ssh-keygen`, and a browser. Internet access is needed to pull
the service and build the disposable SSH target. No registry login is required.

Copy the **complete image reference by digest** from the selected release into
`MCP_SSH_IMAGE` below. Replace the placeholder; do not use a Git commit SHA as
an image digest. Check out the matching release so its demo and documentation
match the service.

```sh
git clone https://github.com/chrisbennight/mcp-ssh-rs.git
cd mcp-ssh-rs
git checkout v0.1.0
MCP_SSH_IMAGE='ghcr.io/chrisbennight/mcp-ssh-rs@sha256:<digest-from-release>'
docker pull "$MCP_SSH_IMAGE"
python3 examples/quickstart/demo.py start --service-image "$MCP_SSH_IMAGE"
python3 examples/quickstart/demo.py request
```

Follow [request approval](quickstart.md#request-approval) to approve the marker
command, collect its result, and stop the demonstration. Startup uses the pulled
service image and builds only the disposable target. For real hosts, follow
[the operating guide](operations.md) and the
[design's preconditions](design.md#non-goals-and-preconditions).

## Identify a running version

Keep the release tag, source revision, image digest, and configuration revision
in your deployment record. GitHub release notes associate the source and image.
SHA tags identify source commits but can be replaced by a rebuild; a digest
identifies exact image content. There is no moving `latest` tag.

For a Docker container, replace the example name with your service container:

```sh
docker inspect --format '{{.Config.Image}} {{.Image}}' your-service-container
docker image inspect --format '{{json .RepoDigests}}' "$MCP_SSH_IMAGE"
```

The first command reports the launch reference and local image ID; the second
reports registry digests for the selected image. A local image ID is not the
registry digest. Compare the registry digest with the release record.

## Upgrade and recover

1. Read the new release notes and compatibility limits. Retain your current
   image digest and configuration before changing anything.
2. Pull the new digest and test it with disposable targets and your intended
   client. Check command review, result collection, and any file channel you use.
3. Stop accepting new work and reconcile running operations using their records
   and the target state. Preserve audit records according to your retention setup.
4. Replace the service with the new digest and compatible configuration. Check
   health and reconnect clients with new sessions. Follow
   [approvals and recovery](operations.md#approvals-and-recovery) for restart effects.
5. If validation fails, stop the replacement and launch the retained digest with
   its matching configuration. Recheck health and start new sessions. Rollback
   changes the service software; it does not undo commands or remote file writes.

The first release has no earlier published release to roll back to. For later
upgrades, keep a tested deployment record rather than assuming that an older
image accepts newer configuration. Investigate an unknown command or transfer
outcome before repeating it.
