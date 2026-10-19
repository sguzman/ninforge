# Roadmap and release discipline

Goal: eventually support **all major Nintendo console generations**, not just the Switch. Priorities blend Nintendo's worldwide hardware popularity, format ubiquity, current utility, and testability. Historical hardware sales are an imperfect demand proxy; they are not a promise that every feature is equally useful for every platform.

Reference: [Nintendo IR, worldwide hardware sales, June 30 2026](https://www.nintendo.co.jp/ir/en/finance/hard_soft/index.html). Examples: Switch 156.59m, DS 154.02m, Game Boy/Color 118.69m, Wii 101.63m, GBA 81.51m, 3DS 75.94m. Switch 2 is an active, growing platform, so support should be reassessed periodically rather than frozen at current lifetime sales.

## Implementation queue

| Phase | Platforms | Why | Initial goal |
|---|---|---|---|
| 1 | **Switch** | Current Cheatarium/Eden pain + biggest installed base | NSP/PFS0 -> XCI/HFS0 (basic inspection done), NCA (plaintext header), CNMT and NACP readable metadata (done); build ID from NSO (done), encrypted NCA support still pending |
| 2 | **DS** | Massive installed base; approachable unencrypted headers | NDS headers/regions and basic FNT/FAT filesystem (done), banners, save identification |
| 3 | **GB/GBC and Wii** | Very popular and widely archived | cartridge header/catalog + Wii disc/WBFS inspection |
| 4 | **GBA and 3DS** | Popular; 3DS adds encrypted containers | GBA headers, CIA/NCSD/NCCH metadata, opt-in external keys |
| 5 | **NES/SNES and N64** | Legacy preservation, small files | mappers, SNES headers, N64 byte orders and checksums |
| 6 | **GameCube and Wii U** | Disc/container work; smaller installed bases | GCM/ISO, WUD/WUX, partition information |
| 7 | **Switch 2, Virtual Boy, Game & Watch, other variants** | Growing / niche platforms | research formats, legal test fixtures, add adapters only with evidence |

Within each phase, deliver: recognition -> trustworthy metadata -> validated directory -> selective extraction -> verification -> backups/save format adapters -> explicit safe write operations. Format support must be granular, not one binary "supported" flag. Some older platforms are already recognized during phase 1 because their headers are cheap to parse.

## Cross-cutting work

1. **CLI and library stability:** stdout text and JSON, descriptive errors, bounded streaming IO, consistent exit codes.
2. **Save discovery/backups:** user-configured paths; no assumption that emulator save labels match in-game slots. Enumerate and back up first, game-specific editing later.
3. **Cheatarium interface:** JSON metadata for title/build/version matching. For Switch, build ID requires identifying the relevant executable, not guessing from the filename or title ID.
4. **Opt-in decryption:** never bundle keys, never echo secrets in logs; avoid promising decrypted metadata for encrypted content.
5. **Provenance:** synthetic fixtures, minimal licensed homebrew samples, fuzzing, property tests, no copyright material in Git history.
6. **Release gates:** compilation, fmt, clippy, tests, fixture audit, release notes; tag semver only after passing checks.

## MVP exit criteria

- CLI prints correct format and safe failure for invalid/truncated inputs.
- Recursive inventory streams NDJSON without buffering complete game collections.
- NSP/PFS0 lists entries and selectively extracts without clobbering files.
- CI exercises good and malformed **synthetic** fixtures; repo asset audit passes.
- Documentation accurately distinguishes detected, partially parsed, and unsupported formats.
- No commercial ROMs, saves, or console keys in any tracked file or release artifact.

## Package correlation MVP

Implemented: explicit plaintext CNMT + PFS0 NSP name-and-size audit, structured content statuses, machine-readable output, optional streaming SHA-256 comparison of NCA bytes against unverified CNMT hashes, and optional read-only user-supplied NACP and user-designated main NSO metadata. External evidence is never implicitly linked to the package. Does not authenticate CNMT provenance, decrypt encrypted meta NCAs, verify SHA-256, derive executable NSO build IDs from encrypted content, or automatically associate multiple installed game versions. These remain future work.

## Save inventory MVP

Implemented: extension-based, read-only candidate enumeration plus explicit, non-overwriting single-file backup. **Not implemented**: automatic emulator discovery, save-file format validation, game-to-save matching, save editing, or directory-wide transactional backups. Those require separate platform adapters and adversarial tests.
