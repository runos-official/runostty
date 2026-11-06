# Changelog

All notable changes to the RunOS terminal server (runostty) are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release workflow takes the GitHub release notes from the section whose
heading is exactly the pushed tag (`## vX.Y.Z` for a final, `## vX.Y.Z-rc.N` for a
candidate), so every released version needs a section here. `package.json` holds
the version of the next final, and a candidate of it shares that number.

## v0.1.0

First versioned release of the terminal server. New terminal pods use it as the `latest` image. The same commit shipped as the release candidate v0.1.0-rc.1.

### Changed
- Node.js moves from the 22.x line, installed from the NodeSource script at build time, to Node.js 24.22.1 from the official image, pinned by digest, so every build gets the same runtime.
- The image is built from a version tag by the release workflow, with a provenance attestation and a release page. A candidate moves the `dev` image tag and a final moves `latest`. A push to main no longer builds an image.
- A pre-push hook stops a push that adds an internal identifier or a credential, and the release script runs the leak gate of a public repo.

## v0.1.0-rc.1

Release candidate of v0.1.0: Node.js 24.22.1 pinned by digest, a versioned and attested image built from the tag, and the release tooling. It moves the `dev` image tag.
