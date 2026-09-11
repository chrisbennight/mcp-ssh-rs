# Dependency security assessment

## RUSTSEC-2023-0071: RSA timing side channel

Assessed on 2026-09-11 against `rsa` 0.10.0-rc.18, `russh` 0.62.6,
`ssh-key` 0.7.0-rc.11, and `aws-lc-rs` 1.18.0.

[RustSec's advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
reports a private-key timing side channel and lists no patched release.
Upgrading the package alone does not resolve it. The service instead uses
AWS-LC for RSA authentication signatures in `connect::rsa::RsaSigner`.
It never gives an RSA private key to russh's built-in signing path.

The remaining RustCrypto RSA use is public-key verification in the SSH stack
and conversion of an operator-provided OpenSSH key into PKCS#1 for AWS-LC
import. Conversion occurs before dialing the target, using fixed key material;
it does not process a peer's message, ciphertext, or authentication transcript.
The conversion uses the library's key-format implementation, including its
private-component calculations. This is not a claim that all RSA code in the
dependency graph is constant-time. An attacker able to replace the service's
credential material or inspect its local process is outside this assessment.

JWT identity verification uses jsonwebtoken's AWS-LC backend and still accepts
only EdDSA assertions. The former RustCrypto JWT backend and its separate
`rsa` 0.9 dependency are absent from the lockfile.

The application-specific exception in `.cargo/audit.toml` covers this advisory
only. `.ci/audit.py` refuses changes to the assessed RSA version or extra
exception IDs. Reassess the call paths when changing SSH authentication,
credential handling, or cryptographic dependencies. Remove the exception when
the affected dependency can be removed or an upstream fix is available.
Other vulnerability findings and yanked dependencies fail the gate.

Regression coverage lives in `connect::rsa::tests` and `connect::tests`:
SHA-256 and SHA-512 signatures verify through the SSH library; changed messages
and unexpected identities are rejected; a loopback server authenticates an RSA
credential; a legacy-only server cannot cause fallback to SHA-1 signing.
These tests establish routing and interoperability, not a timing-security proof
of AWS-LC. The upstream cryptographic implementation remains a dependency.

## RSA compatibility

RSA credentials must be unencrypted OpenSSH keys accepted by AWS-LC
(2048–8192 bits), and the target must support `rsa-sha2-256` or `rsa-sha2-512`.
The public key can still have the `ssh-rsa` format label. Legacy SHA-1
authentication signatures are refused; use a SHA-2-capable server or an
Ed25519/ECDSA credential instead. OpenSSH describes the distinction in its
[8.8 release notes](https://www.openssh.com/txt/release-8.8).

## Yanked releases

The lockfile uses `chacha20` 0.10.2 and `wnaf` 0.14.1 in place of the yanked
0.10.1 and 0.14.0 releases. The advisory gate checks yanked status on every CI
run; this record does not establish that a release will never be yanked later.
