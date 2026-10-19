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
