# Run a local demonstration

This tutorial starts the service and a disposable SSH target on your computer.
It uses standalone authentication, so you do not need a gateway, identity
provider, or lab account. The target contains a normal `demo` account, with no
sudo access. Nothing connects to your existing SSH hosts.

## Prerequisites

- Docker with a local Linux daemon and Docker Compose v2 or newer.
- Python 3.11 or newer and OpenSSH's `ssh-keygen` on your computer.
- Internet access to obtain the public base images, Debian packages, and Rust
  dependencies during the first build. Building from source takes several minutes.
- A current browser for the approval page.

Clone the public repository, then run the commands below from its root:

```sh
git clone https://github.com/chrisbennight/mcp-ssh-rs.git
cd mcp-ssh-rs
```

This tutorial builds from source; it does not require a published binary or
access to a prebuilt service image.

## Start

```sh
python3 examples/quickstart/demo.py start
```

Use `start --port 18080` if port 8080 is occupied. The helper generates separate
MCP and operator credentials, an SSH client key, and a target host key in
`.quickstart/`. It builds both containers and waits for them to be healthy.
It publishes the service only on `127.0.0.1`; the SSH target has no published
port, and the containers share an internal Docker network.

The registry pins the target's generated public key directly. It does not
trust an unknown key obtained from a live server. Generated private material
is excluded from Git and the Docker build context. Do not commit it, paste it
into chat, or give an agent access to the operator password or SSH key.

The helper prints the dashboard URL. The operator name is `operator`. Open
`.quickstart/operator-password` in a local editor to obtain its password;
the helper does not print credentials. The browser asks for these when you
open the dashboard. This local HTTP login is for the tutorial; see
[operating the service](operations.md) before using remote connections.

## Request approval

```sh
python3 examples/quickstart/demo.py request
```

The supplied Python MCP client initializes the connection, opens a session,
and asks to run `touch /home/demo/tutorial-marker`. The result should have
`outcome: "awaiting_approval"` and a link to the approval page. No file has been
created yet. Keep the session and request identifiers as returned; they are
not credentials and are not constructed by the client.

The tutorial marks the writable demo account privileged and enables local
review for privileged accounts. Every command on that account requires review,
regardless of its text. The label does not grant root access: the target still
executes as the non-root `demo` account with its configured operating-system
permissions.

Open the dashboard URL, log in, and review the host, role, command arguments,
and declared purpose. Choose **Approve once** for the marker command. Approval
does not itself execute the command: the client must collect the decision.

```sh
python3 examples/quickstart/demo.py collect
```

After approval, the result should be `outcome: "ran"` with `exit: 0`. The helper
polls a running command instead of sending it again, then closes the session.
If you have not answered yet, it reports that approval is still required.

## Inspect the record

```sh
python3 examples/quickstart/demo.py logs
```

The local service logs contain the session, decision, human answer, and command
outcome. The actor for MCP work is `local`; the approving operator is
`operator`. The optional durable-history reader is not configured in this
tutorial, so the dashboard's historical pages report it unavailable. Container
logs provide the tutorial record and are removed by teardown; they are not a
production retention setup.

## Use another MCP client

The supplied client is the small Python implementation in
[`demo.py`](../examples/quickstart/demo.py). For a tested external client, follow
the [MCP Inspector CLI walkthrough](clients.md). A compatible non-browser client
uses Streamable HTTP at `http://127.0.0.1:8080/mcp`, with an
`Authorization: Bearer ...` header supplied from `.quickstart/mcp-token` through
its credential configuration. Use your selected port if different. The service
advertises MCP protocol version `2025-11-25`.

Clients must send the MCP token on every request. They do not send a principal
argument or `x-mcp-identity` header in standalone mode. Clients sharing the
token share the configured identity; see the [authentication design](design.md#account-authorization)
before sharing a deployment. Browser-based MCP clients and OAuth login are not
part of this setup.

## Stop and remove the demonstration

```sh
python3 examples/quickstart/demo.py stop
```

This removes the demonstration containers, network, and generated local files.
Downloaded and built Docker images remain cached. If startup fails after
configuration was generated, the same stop command removes its resources.

## Common failures

- **Port already in use:** stop this demonstration, then start with another
  `--port`. A running demonstration retains the port recorded at initialization.
- **MCP returns 401:** check that the client uses the MCP token, not the operator
  password, and does not send an identity or browser `Origin` header.
- **The browser keeps asking for a password:** use the operator name and the
  separate operator password. Browser HTTP login may remain cached until the
  browser session closes.
- **Approval submission is refused:** use a current browser on the dashboard's
  own origin. Cross-origin submissions are refused.
- **A session is unknown after restart:** sessions and outstanding approvals are
  process-local. Start a new tutorial request after removing the old
  `.quickstart/request.json` identifier file. Do not repeat an arbitrary command
  if its execution outcome is unknown; the marker operation here is disposable.
- **Build cannot reach a registry:** the first build needs public network access.
  The optional private crate mirror is not needed.
