# Find the right guide

Start with the task you want to complete. New users can try the local demo
before configuring any existing SSH host.

| I want to… | Start here | What you need |
| --- | --- | --- |
| See a command reviewed and completed | [Local demonstration](quickstart.md) | Docker with a Linux daemon, Compose, Python, OpenSSH tools, and a browser |
| Connect an MCP client | [Tested client walkthrough](clients.md) | A running demo; Node.js for MCP Inspector CLI |
| Choose standalone or gateway access | [Authentication](operations.md#choose-authentication-explicitly) | An operator-controlled deployment |
| Configure my own SSH host | [Add a host](operations.md#add-a-host) | A target account, its credential, and a verified host key |
| Upload files or retrieve large output | [File transfers](file-transfers.md) | A configured byte channel and an authorized SSH session |
| Review requests and recover interrupted work | [Approvals and recovery](operations.md#approvals-and-recovery) | Access to the operator surface and target administration when needed |
| Collect records or enable optional integrations | [Logs and integrations](operations.md#logs-and-optional-integrations) | An operator-managed destination |
| Configure outbound certificate trust | [Outbound connections](outbound-connections.md) | Your deployment's certificate authorities |
| Understand the scope and architecture | [Design](design.md) | Start with its non-goals and preconditions |
| Assess dependencies or RSA compatibility | [Dependency security](dependency-security.md) | The version you plan to deploy |

For setup failures, start with [quickstart troubleshooting](quickstart.md#common-failures).
For questions or reproducible defects, see [Get help](../SUPPORT.md).
Use [Security reports](../SECURITY.md) for vulnerabilities.

## Contribute or maintain a release

[Contributing](../CONTRIBUTING.md) explains useful first contributions and local
validation. Its maintainer sections cover repository administration and image
publication. [Releasing](releases.md) is the maintainer's publication checklist;
[the changelog](../CHANGELOG.md) describes release status and changes.
