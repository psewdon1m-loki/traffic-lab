# Traffic Lab CI and release contract

The workflows follow the project's unification specification, Part V and
acceptance item 39. The specification is maintained outside this repository;
this file records the resulting repository-local release contract.

## Pre-merge and branch CI

`.github/workflows/ci.yml` runs on pull requests and pushes to `main`. It does
not publish releases. It validates Bash and PowerShell entry points, restores
.NET and Gradle dependencies from committed lock/checksum metadata, runs shared
self-tests, builds all three distributions, smoke-tests the exact Windows and
Linux binaries, installs the Linux archive in a clean Ubuntu container, and
verifies the Android package signature and embedded version. Successful jobs
retain short-lived CI artifacts for inspection.

## Immutable release workflow

`.github/workflows/release.yml` has only a stable semantic tag trigger. There is
no branch, pull-request or manual publication trigger. A release starts with:

```bash
git tag v3.2.2
git push origin v3.2.2
```

The workflow rejects a tag that does not point at the checked-out commit or
does not exactly equal the `<Version>` in the .NET project. It builds and tests
Windows, Linux and Android independently, then downloads those exact tested
objects, verifies every SHA-256 sidecar and component manifest, generates the
multi-platform release contract and GitHub build-provenance attestations, and
publishes only under the original tag. An already existing release causes a
fail-closed error; assets are never silently replaced.

Published files include:

- `LokiTrafficLab-windows-x64-VERSION.zip` and SHA-256;
- `LokiTrafficLab-linux-x64-VERSION.tar.gz`, SHA-256, `bootstrap.sh` and its
  SHA-256;
- `LokiTrafficLab-android-VERSION.apk` and SHA-256;
- three component manifests, `release-manifest.json`, `SHA256SUMS`, and
  `INSTALL-LINUX.txt` with the exact one-command installation line.

## Trust boundaries

Checksums provide byte integrity, not publisher authentication. GitHub artifact
attestations bind CI-produced release files to the tag workflow, but consumers
must actually verify those attestations for enforcement. The Android APK is
currently signed with the build environment's debug identity; it is intended
for direct testing, not app-store publication or stable-key in-place upgrades.
The release command verifies `bootstrap.sh` against the release contract and
the bootstrap verifies the Linux archive sidecar, while initial trust in the
release page/manifest still depends on GitHub HTTPS and repository controls.
