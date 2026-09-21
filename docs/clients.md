# Connect an MCP client

Start the [local demonstration](quickstart.md#start) first. It supplies a
disposable SSH account and separate client and operator credentials.

## Tested client: MCP Inspector CLI

[MCP Inspector](https://github.com/modelcontextprotocol/inspector) is an
interactive and command-line client for inspecting MCP servers. This guide uses
its CLI, with version 2.4.0, Node.js 22.23.2, Linux, Streamable HTTP, and
standalone authentication. Inspector requires Node.js 22.19.0 or newer.

The [demo adapter](../examples/quickstart/inspector.py) invokes that Inspector
version through `npx` and reads the running demo's port and token. Its first run
may download the public package. The token goes through an in-memory stdin
configuration, not a command argument or saved Inspector catalog. The adapter
uses Linux's `/dev/stdin` and selects Inspector's legacy protocol era for this
server's advertised MCP version, `2025-11-25`.

Run commands from the repository root:

```sh
python3 examples/quickstart/inspector.py --method tools/list
python3 examples/quickstart/inspector.py --method tools/call --tool-name ssh_hosts
```

The first response lists the SSH tools; the second includes the `demo` host and
`user` role. Open a session:

```sh
python3 examples/quickstart/inspector.py --method tools/call --tool-name ssh_open_session \
  --tool-args-json '{"host":"demo","role":"user","access_class":"privileged","purpose":"Try MCP Inspector with a disposable file"}'
```

Copy the returned `session` identifier into `SESSION_ID` below. It is an
identifier, not a credential.

```sh
python3 examples/quickstart/inspector.py --method tools/call --tool-name ssh_exec \
  --tool-args-json '{"host":"demo","role":"user","access_class":"privileged","session":"SESSION_ID","intent":"Create an Inspector tutorial marker","command":["touch","/home/demo/inspector-marker"]}'
```

Expect `outcome: "awaiting_approval"`. Use the operator login and dashboard URL
from the [tutorial](quickstart.md#request-approval), review this request, and
choose **Approve once**. Run the same `ssh_exec` invocation once to collect the
decision. When it returns `outcome: "ran"` and `exit: 0`, the command completed.

If the response is `still_running`, use the returned `run` identifier with
`ssh_poll` rather than repeating execution:

```sh
python3 examples/quickstart/inspector.py --method tools/call --tool-name ssh_poll \
  --tool-args-json '{"host":"demo","role":"user","access_class":"privileged","session":"SESSION_ID","run":"RUN_ID"}'
```

Close the session after collecting the result:

```sh
python3 examples/quickstart/inspector.py --method tools/call --tool-name ssh_close_session \
  --tool-args-json '{"host":"demo","role":"user","access_class":"privileged","session":"SESSION_ID"}'
```

Stop the demo with `python3 examples/quickstart/demo.py stop` when finished.
Inspector commands use their own session; the Python tutorial's `collect`
command only collects a request created by its own `request` command.

## Compatibility limits and troubleshooting

The supplied [Python tutorial client](../examples/quickstart/demo.py) and the
Inspector CLI flow above cover discovery, command review, and result collection.
Inspector's web UI, other client versions, stdio client configurations, and
file-byte transfer through Inspector have not been verified by this walkthrough.
The demo does not enable a file byte channel; follow
[file transfers](file-transfers.md) to configure one. Tool discovery alone does
not prove that a client can upload or download file references.

- **Cannot connect:** confirm the demo is running and use its recorded port.
  The adapter reads that port automatically.
- **Unauthorized:** use the MCP token for MCP requests and the separate operator
  password for the review page. Restart the client after demo teardown/recreation.
- **Waiting after approval:** collect with the same session, command, and intent
  you originally submitted, then poll if still running.
- **Unknown session:** the service may have restarted. Follow
  [recovery guidance](operations.md#approvals-and-recovery) before repeating work.

Other non-browser clients may work with the documented
[transport](operations.md#transport-and-output-destinations) and
[authentication](operations.md#choose-authentication-explicitly) interfaces;
they are unverified until tested. OAuth login and direct browser MCP connections
are outside this setup. To report a tested combination, include the client
version, transport, and observed results in a contribution or issue.
