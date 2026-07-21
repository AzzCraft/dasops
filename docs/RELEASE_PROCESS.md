# Release Process

## Validation gate

`.github/workflows/release.yml` is manual-dispatch only. The dispatch must run
the workflow itself from the default branch and name the exact annotated `v*`
tag in `ref`; the workflow resolves the tag, its tag object, target commit,
and `VERSION` before it runs target code. This permits validation of a
historical tag without moving it. Tag-source validation has read-only contents
permission only; a separate fresh trusted job re-resolves the same tag,
rebuilds and extracts the source archive without executing tag code, then
receives the attestation permissions. It runs
the public verification gate, `pip-audit` against the pinned verification lock,
and Bandit against `dasops`. The workflow then creates a deterministic `git
archive` source tarball (`gzip -n`), a deterministic SPDX 2.3 source inventory
from the exact commit (tracked-file checksums and a package-verification code),
a canonical tag-object/commit/version manifest, and `SHA256SUMS` for the
evidence set.

The evidence is uploaded as a retained Actions artifact; the independently
rebuilt source archive is covered by a GitHub artifact provenance attestation.
It provides verifiable build evidence, but does not replace a maintainer's
signed release tag.

The workflow verifies an annotated tag and its target commit, not an approved
GPG, SSH, or Sigstore signer. Cryptographic tag verification remains a
protected publication gate until the release owner publishes the signer trust
policy and verification evidence.

The generated source inventory records source-tree identity only. It is not a
third-party dependency or license-compliance SBOM, and cannot by itself satisfy
a release-truth-pack dependency or license SBOM requirement.

## Publication

The validation workflow has read-only repository contents permission. It does
not create a tag, move a ref, or create a GitHub Release. An authorized release
owner must create the signed immutable `v<version>` tag through the protected
review path first; validation then binds its evidence to that exact tag. After
a green run, the owner verifies the artifact checksums and provenance and
separately publishes the release.

Legal holder: AzzCraft Inc. (重庆艾之舟科技有限公司)
