# Releasing

remoteexec uses semantic versions and remains pre-1.0. Incompatible public CLI
or result-schema changes increment the minor version; compatible fixes
increment the patch version.

1. Add a dated section for the version to
   [`CHANGELOG.md`](https://github.com/rubyattack3r/remoteexec/blob/v0.2.0/CHANGELOG.md).
2. Run `make verify` and require the complete `develop` CI workflow to pass.
3. Fast-forward `main` to the reviewed `develop` commit and require `main` CI
   to pass.
4. Create and push an annotated `vX.Y.Z` tag at that exact `main` commit.
5. The tag-triggered Publish workflow verifies the source, extracts the
   matching changelog section, and runs GoReleaser.
6. Confirm the GitHub release contains Linux, macOS, and Windows archives for
   amd64 and arm64, checksums, SBOMs, and Sigstore bundles.

Never move an existing release tag. If publishing fails, fix the release path
in a new commit and use a new version after removing any incomplete draft or
release created for the failed tag.
