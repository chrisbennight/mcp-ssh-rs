# Outbound connections

Gateway signing-key discovery, approval notifications, and Loki history reads
accept HTTP and HTTPS. Use HTTPS when a connection crosses an untrusted network.
Plain HTTP remains available for a protected internal hop or local testing.
This does not add TLS termination to the service's incoming HTTP listener.

| Setting | Endpoint |
| --- | --- |
| `MCP_SSH_IDENTITY_JWKS_URL` | The gateway's JSON Web Key Set. Requires a host; credentials, query strings, and fragments are rejected. |
| `MCP_SSH_NOTIFY_URL` | An optional webhook that accepts the service's notification JSON. |
| `MCP_SSH_AUDIT_QUERY_URL` | An optional Loki base URL, such as `https://logs.example/`. Paths, credentials, query strings, and fragments are rejected. |

The clients verify certificate trust, validity dates, and the endpoint hostname.
There is no setting to disable certificate verification. They do not follow
redirects, including an HTTPS redirect to HTTP; configure the destination URL
directly. They also ignore proxy settings from the process environment. Existing
request deadlines and response limits still apply.

## Certificate trust on Linux

The Rustls client uses the platform trust store. The runtime image includes the
Debian CA bundle. A public endpoint with a certificate trusted by that bundle
needs no additional TLS configuration.

For a private certificate authority, mount an operator-managed PEM certificate
bundle read-only and set `SSL_CERT_FILE` to its path inside the container. Set
`SSL_CERT_DIR` to a mounted, empty directory if you want only that bundle to be
trusted. These variables select the certificate sources; they do not implicitly
append your bundle to the default roots. Include any public roots you still
need in the selected bundle. Restart after changing the trust configuration.
Only public CA certificates belong in this bundle; do not mount a CA private key.

These Linux trust-source settings come from
[`rustls-native-certs`](https://docs.rs/rustls-native-certs/0.8.4/rustls_native_certs/fn.load_native_certs.html).
Other operating systems have different platform trust behavior and are not
covered by the container checks.

## Failed connections

An unavailable or untrusted gateway key endpoint leaves identity verification
unavailable; it does not admit unsigned callers. Startup can continue while the
gateway recovers. Failed notifications leave the request in the dashboard and
write a delivery warning without logging the endpoint URL. An unavailable Loki
endpoint makes the history page report its source unavailable.

If TLS fails, check the endpoint hostname, certificate expiry, server chain,
and configured CA bundle. Do not work around it by disabling verification.
Use the endpoint's final URL when it redirects.

HTTPS protects transport; it does not add an authentication scheme to an
integration. The Loki reader uses deployment-supplied `MCP_SSH_AUDIT_LABELS`.
It does not configure tenant or authorization headers; deployments requiring
those need a separately configured protected adapter.
