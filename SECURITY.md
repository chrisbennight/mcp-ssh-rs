# Security reports

Security fixes target `main`. There are no maintained stable release branches
or promised response times.

Use [GitHub's private vulnerability report form](https://github.com/chrisbennight/mcp-ssh-rs/security/advisories/new).
Private vulnerability reporting is enabled for this repository. Sign in to
GitHub and choose **Security → Advisories → Report a vulnerability** to send
the report privately to the repository maintainers. Do not post vulnerability
details in public issues or pull requests.

In the private report, include the commit or image digest, affected deployment
mode, expected behavior, observed behavior, and a minimal reproduction using
disposable targets. Remove credential values and unrelated operational data.
Do not test systems you do not own or have permission to assess.

The [design](docs/design.md) describes the intended security boundaries.
[Dependency security](docs/dependency-security.md) records the current advisory
assessment and RSA compatibility. A passing dependency scan is not a security
assessment of a deployment.
