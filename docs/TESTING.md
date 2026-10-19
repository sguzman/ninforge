# Test strategy / no copyrighted fixtures

**Default rule: fixtures are constructed in test code, not checked into the repository.** The unit tests build a tiny synthetic PFS0 with text content; NES, DS/NitroFS, GB/GBC and GBA are tested with programmatically constructed dummy headers. No retail ROM, game save, Nintendo logo image, keys, or proprietary asset is required for the tests. The GB boot header logo byte sequence is a format identifier, not a playable game image.

`cargo test --all-targets` runs tests. GitHub Actions also checks formatting and clippy. The tracked-filename guard catches common game image and key extensions, but it cannot detect content deliberately disguised with a benign extension: **human review of staged content is mandatory**.

Allow a small homebrew/test ROM in the future only if:

1. Its license explicitly permits redistribution in a public repository.
2. Its origin, author, license, purpose, and SHA-256 are documented.
3. It contains no retail code, dumps, proprietary keys, copyrighted Nintendo artwork or private save data.
4. It is demonstrably needed for a test that synthetic bytes cannot exercise, with the smallest feasible size.
5. It is granted a specific exception to the CI asset guard, not a broad bypass.

Negative tests cover truncation, offset overflow, string table limits, duplicate names and overlapping regions. Future tests should cover malformed UTF-8, symlink/path edge cases and fuzzing. Long-term additions: fuzzing and corpus minimization, property tests, cross-tool comparison against legitimately obtained local files without uploading them.

The repository CI is authoritative for compilation where a Rust toolchain is available. Do not claim successful local compilation unless tests were actually executed.

## Save safety tests

Synthetic byte strings only: candidate extensions, nested directories, no-overwrite backups, source immutability, and symlink refusal (on Unix). The backup uses same-directory hard links for no-clobber publication; filesystems without hard-link support produce an error rather than unsafe replacement. No user save, emulator configuration, or game data is stored in the repository.

## Switch HFS0 and XCI

Synthetic HFS0 entries and a nested XCI root partition are generated in memory. Negative tests reject unsafe filenames, impossible hash spans and truncated data. SHA-256 values and XCI signatures are **not** verified.

## Switch control.nacp

Tests synthesize only unencrypted 0x4000-byte control metadata with fictional homebrew strings. Parsing fails closed on missing titles, invalid UTF-8, truncation and compressed or unknown title-table encodings. No keys or real title assets are needed.

## Switch NSO and cheat ID

A synthetic NSO0 header verifies that the Atmosphère cheat ID uses the first eight bytes of the module build ID. A zero-filled ID reports explicit unavailability.

## NCA and CNMT

Synthetic test headers only: keyless/decrypted NCA headers with content type, title/program ID, section bounds, and invalid overlapping or oversized sections; plaintext CNMT files with title ID, version, patch relation, referenced content IDs, malformed counts and truncation. No keys, retail NCAs or game data are stored. No cryptographic validation is claimed.

## Package-level metadata audit

Synthetic in-memory NSP entries and plaintext CNMT records are correlated by exact 16-byte hexadecimal content ID and expected NCA name, without decryption. Tests cover matched and missing content, mismatched lengths, unsupported `.ncz` compression, duplicate case variants, meta `.cnmt.nca` filenames, and unrelated/non-NSP inputs. Passing the audit is **not** proof of title authenticity or validated SHA-256 hashes.

## External title and executable evidence

Package audit tests construct an entirely synthetic 0x4000-byte NACP and NSO0 header. The evidence attaches only when explicitly supplied; malformed NACP, non-NSO files, and duplicate attachment attempts are rejected. The CLI accepts `--nacp`, `--main-nso`, and `--json` without order dependence after the required NSP and CNMT paths, rejecting duplicates and missing flag values. The JSON payload retains separate evidence provenance and `linked_to_package: false`, even when titles and build IDs are present. No title-to-executable association is cryptographically verified.

## Optional full-content SHA-256 checks

CNMT content records preserve their 32-byte SHA-256 digest. In-memory synthetic NSP/PFS0 fixtures prove that `--hash` hashes the NCA entry rather than the entire package wrapper (known SHA-256 of `abc`), detects same-length byte corruption, refuses to claim verification when files are missing or compressed, and skips hashing in the default fast audit. SHA-256 is implemented with the pure-Rust `sha2` crate. A digest match validates only correspondence to the user-provided CNMT, **not title authenticity**: external CNMT provenance and signatures remain unverified.

## Metadata directory discovery

The `package audit-dir` shortcut never recurses, never follows symlinks, and refuses competing `.cnmt` or `.nacp` sidecars. Only `main.nso` is considered the designated executable; unrelated `.nso` files are ignored. Tests cover unique, absent, duplicate, nested and symlink candidates. Supplying files in a common directory is not proof of common title provenance.

## XCI package correlation

Synthetic nested XCI/HFS0 root-and-secure partitions are used to verify CNMT reference matching, SHA-256 checks of NCA byte ranges and rejection of tempting decoy names outside `root/secure/`. The older `audit_nsp` API continues rejecting XCI, while new generic package-audit APIs and the CLI support both NSP and XCI. A matched hash confirms only correspondence to the separately supplied, unauthenticated plaintext CNMT.

## Plaintext NCA header cross-check

`package audit --headers` checks only uniquely identified NCA entries using a bounded first-0x400-byte read. Unit tests cover matching type and size, separately reported NCA program IDs, mismatched content type or size, raw encrypted header detection as unavailable, malformed plaintext NCA headers, and missing referenced NCAs. This remains separate from the optional full SHA-256 digest comparison: neither step authenticates the external CNMT or establishes ownership of an attached main NSO.

## Version-aware title inventory

Synthetic sidecar bundles are indexed one directory deep only, ordered by folder name and grouped by claimed application ID. Cases cover base-versus-patch version distinctions, highest supplied patch revision, identical duplicate releases, conflicting same-title/version CNMT digest pairs, missing or malformed plaintext metadata, and symlinked bundle rejection. CLI JSON schema version 1 is kept separate from package audit JSON and explicitly states that attached NACP/NSO evidence is not authenticated.

## Combined title and package inventory

The optional `titles inventory <root> --packages` uses only files exactly named `package.nsp` or `package.xci` within each immediate bundle. The integration tests use synthetic CNMT+PFS0 fixtures to verify default metadata-only behavior, size-only matches, streamed SHA-256 matches, same-size tampering, bounded readable header checks, optional missing packages, ambiguous candidate refusal, flag validation, and symlink refusal. Package audit status remains nested under its originating title record. The source CNMT and the associated NACP/NSO are not authenticated.
