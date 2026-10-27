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

The evidence is uploaded as a retained Actions artifact. The final
`dasops-<version>-evidence.tar` is the direct subject of the GitHub
artifact provenance attestation; its inner source archive is not that subject.
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

## Fixed beta offline materials

For the exact tool version `1.2.0-beta.1`, all three dispatch inputs are required:
`materials_artifact_id`, `materials_run_id`, and `materials_sha256`. They remain
optional in the workflow declaration for historical versions; do not supply
empty values for this beta or change the historical validation route.

1. A release maintainer prepares an independently reviewed materials directory.
   `build-materials.json` contains `imageId` (immutable Docker `sha256:` ID),
   `platform: "linux/amd64"`, and integer `sourceDateEpoch`. Use a Python image
   containing the interpreter/venv needed by the fixed worker; the workflow does
   not pull a moving image tag. For a fresh hosted runner include `imageArchive`
   with its relative `path` and raw 64-character `sha256`, unless the exact image
   is already available there.
2. Add `buildWheels`, a mapping with exactly the setuptools, wheel and packaging
   wheel filenames. Each value has relative `path` and raw `sha256`; match the
   reviewed build dependency pins. The fixed builder is delivered at
   [`tools/build_tool_assets.py`](../tools/build_tool_assets.py) in the public repository (shared source
   with Cadence). Do not replace it with code supplied by the candidate.
3. Run `gh workflow run prepare-materials.yml --ref main --repo AzzCraft/dasops`.
   The reviewed default-branch workflow downloads only the fixed Python image,
   official Go archive or three PyPI wheels; verifies their pinned identities;
   and uploads `dasops-build-materials-<run_id>-<run_attempt>`.
   It has read-only repository permissions and no signing or release authority.
   The selected platform, upstream SHA256 values and beta epochs are in
   [`prepare_build_materials.py`](../tools/prepare_build_materials.py). Review changes to those constants
   before running a different material set. Docker archive bytes can vary across
   Docker versions; bind the actual saved archive in the generated manifest.
   An old local manifest digest must not be substituted for this run's digest.
   The run summary reports all three inputs below. Artifact transport retains
   Go modes inside its tar; the release workflow downloads the single selected
   ID directly into the material directory using `merge-multiple: true`.
4. Record that run's numeric ID and the uploaded artifact's numeric ID. Check
   their association and expiry using
   `gh api repos/REPOSITORY/actions/artifacts/ARTIFACT_ID`; its `workflow_run.id`
   must equal `materials_run_id`, and `expired` must be false. Download/read back
   the selected artifact; compare every material and `sha256sum build-materials.json`
   with the independently retained expected values. `materials_sha256` is the
   raw manifest byte digest, without `sha256:`, not the outer ZIP digest.
5. Dispatch the reviewed default-branch workflow with the already authorized
   annotated tag and the three recorded inputs. The build job checks their
   presence, manifest digest and selected material bytes before offline build
   and installation testing. It then emits the tool payload and
   `tool-build-binding.json`; the trusted job independently binds both and
   appends them to the final evidence tar with updated `SHA256SUMS`.

## Download and verify the direct subject

After the trusted attestation succeeds, the same tar bytes are retained as the
Actions artifact `dasops-attested-evidence-<run_id>-<run_attempt>`
for 30 days. The artifact service wraps this file in a ZIP; verify the extracted
tar itself, before unpacking or using its contents:

```bash
repo=AzzCraft/dasops
# Fill these with the successful release-validation run and its attempt.
gh run download "$run_id" --repo "$repo" \
  --name "dasops-attested-evidence-${run_id}-${run_attempt}" --dir "$download_dir"
subject="$download_dir/dasops-${version}-evidence.tar"
sha256sum "$subject"
gh attestation verify "$subject" --repo "$repo"
```

Check the verified provenance's repository, workflow and source commit against
the reviewed run. Save the exact tar, its digest and verification output before
retention expires; then inspect members and verify their `SHA256SUMS`. Historical
subjects contain source/inventory/manifest/checksums; this fixed beta also
contains the derived tool and its build binding. A downloaded artifact ZIP,
source tarball, or later repacked tar is not interchangeable with the subject.
This workflow does not create a tag, publish a Release, or provide production
signing authority. Local checks cannot establish hosted attestation success.
