# Releasing

Select a reviewed commit on `main` after required CI checks pass. Validate the
combined result with the [local checks and container checks](../CONTRIBUTING.md#local-checks).
A job that did not start is not a successful check.

Exercise the [Quickstart](quickstart.md) against disposable targets, including
configured account access, human approval, file upload/download, and bulk output.
Verify teardown and record the platform and client actually tested.

## Source and licensing

Inspect an export of tracked files rather than copying a working directory.
Exclude generated credentials, local configuration, private deployment data,
and unrelated artifacts. Run a secret scanner with redacted output and review
its findings. Preserve required third-party notices and verify the dependency
licenses and advisory assessment for the selected lockfile.

Update the single initial release entry in [the changelog](../CHANGELOG.md)
when tagging the first public release. Keep development chronology in Git
history and pull requests. Release notes describe supported behavior, setup,
compatibility limits, the source commit, and tested image digest.

## Distribution

The pipeline publishes a container after successful checks on `main` or a
maintainer-created version tag. Tag the selected commit as `v<workspace-version>`;
the release reference check refuses a tag that disagrees with `Cargo.toml`.
The image uses the same full-commit SHA tag and verified digest on either path.
The pipeline does not create release tags, standalone binary downloads, or crates.io packages.
The workspace crates have `publish = false`. See
[image publication](../CONTRIBUTING.md#github-checks-and-images) for naming and
validation.

Verify package access separately from repository access. Test the documented
pull command without authentication and confirm that its digest matches the
tested image. Deploy by digest and retain a tested rollback digest. Restarting
the process invalidates sessions, pending approvals, and temporary references.

Verify a private reporting route before announcing a public release and keep
[SECURITY.md](../SECURITY.md) current. Repository visibility, release publication,
and deployment are separate maintainer actions.
