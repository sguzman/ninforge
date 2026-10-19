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
