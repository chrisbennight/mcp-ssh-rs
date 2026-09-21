# Security reports

The project is preparing its first public release. Security fixes currently
target `main`; there are no maintained stable release branches or promised
response times.

Use **Security → Advisories → Report a vulnerability** if that option is
available in the repository. It sends a private report to the maintainers.
Availability depends on repository settings; this file does not enable it.

If the option is absent and you do not already have a private maintainer
contact, open an issue titled **Request for private security contact**. Include
only the request for a contact route. Wait for a private channel before sending
vulnerability details, affected hostnames, credentials, logs, or exploit code.

In the private report, include the commit or image digest, affected deployment
mode, expected behavior, observed behavior, and a minimal reproduction using
disposable targets. Remove credential values and unrelated operational data.
Do not test systems you do not own or have permission to assess.

The [design](docs/design.md) describes the intended security boundaries.
[Dependency security](docs/dependency-security.md) records the current advisory
assessment and RSA compatibility. A passing dependency scan is not a security
assessment of a deployment.
