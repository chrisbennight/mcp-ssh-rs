# Preparing a public release

Development remains private while the initial release is prepared. Publishing
the repository, publishing a package, and deploying it to a host are separate
actions. This guide describes the checks before publication; it does not make
the repository or its images public.

## Select the candidate

Choose a reviewed commit on `main`. Require successful tests, dependency audit,
container checks, and automated review for the code being released. A job that
never obtains a runner has not passed. Reconcile overlapping pull requests and
run the checks on the combined result before selecting it.

Run the documented Quickstart from a clean checkout using public build sources
and disposable targets. Verify both a permitted operation and an operation
released through human approval. Check teardown as well as startup. Document
the platform and client actually tested; do not infer support for other CPU
architectures or MCP clients from compilation alone.

## Review the publication snapshot

The selected publication plan is a fresh history containing the current `main`
snapshot. Existing private Git history and issues are not part of the import.
Prepare and inspect an export of tracked files, rather than copying a working
directory with its Git metadata, local configuration, or generated credentials.
Do not delete or recreate the private repository as part of routine development.

Review the exact export for credential material, private endpoints, deployment
identifiers, internal links, personal data, and files whose redistribution rights
are unclear. Use a secret scanner with redacted output and inspect its findings;
test fixtures and secret-like strings still need a disposition. Ignore rules
alone do not prove the absence of tracked secrets. Rotate any real credential
that was exposed; excluding old history does not revoke it.

Confirm that the copyright and license apply to the exported code and that
third-party license obligations are met. Preserve required notices. Recheck
dependency advisories for the selected lockfile and retain the reasoning for
any bounded exception. These checks cover the source and the distribution
artifact, including its base image and installed packages.

## Verify the public entry points

Before changing visibility, verify the maintainer can receive private security
reports and update [SECURITY.md](../SECURITY.md) with the tested route. GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository)
is a repository setting, not something enabled by committing a policy file.
Also verify repository rules, required CI checks, and the review installation
after creating the publication repository.

Update the README's preparation status and make sure its links and clone
instructions resolve for a reader without lab access. Keep optional private
integrations clearly separate from the supported Quickstart. File-transfer
integration remains deferred; do not advertise it as a supported initial flow.

## Distribute a tested artifact

The current pipeline publishes a container after successful checks on `main`.
It does not create GitHub releases, version tags, standalone binary downloads,
or crates.io packages. The workspace crates currently have `publish = false`.
See [Contributing](../CONTRIBUTING.md#github-checks-and-images) for image naming
and the publication check.

Record the source commit and resulting image digest in release notes. Describe
setup, compatibility limits, relevant security changes, and any required
migration. Deploy by digest: rebuilding a commit can replace its SHA tag.
Retain a previously tested digest for rollback and account for process-local
sessions and approvals being lost on restart.

Verify package visibility separately from repository visibility, then test the
documented pull command from an unauthenticated client. Confirm that the pulled
digest is the one tested. A successful authenticated push does not prove that
a new user can obtain the image. Do not announce the release while that check
or a required build/review gate remains unresolved.
