# Ninforge

A **Rust-first, reusable CLI + library** for inspecting Nintendo game files, containers, and save backups across Nintendo console generations. Linux/EndeavourOS is the primary development target; the code should remain portable. No web app, daemon, or mandatory emulator dependency.

**Current status: early format inspection and safe single-file save backups.** The working implementation detects signatures for Switch NSP/PFS0, XCI, readable NCA headers, 3DS NCSD, DS, Wii, GameCube, GBA, GB/GBC, N64, and NES. NSP/PFS0 and HFS0 support bounded entry inspection and extraction. XCI reads the root partition and one nested HFS0 level. DS supports ROM header sections and NitroFS file-tree inspection and extraction. Both perform structural, not cryptographic, verification. Signature recognition **does not** mean full parsing or decryption support. Titles/IDs requiring encrypted control metadata or game-specific save schemas are not yet available.

## Build

Requires Rust 1.82+ (`rustup`/Cargo), Git, and no runtime dependencies:

```sh
cargo build --release
cargo test --all-targets
cargo run -- help
```

For a local install: `cargo install --path .`. On EndeavourOS, use the installed Rust toolchain; no Python, Node, or shell-wrapper runtime is required.

## Usage

```sh
ninforge info ./game.nsp
ninforge info ./game.gba --json
ninforge list ./game.nsp
ninforge list ./game.nsp --json
ninforge list ./game.hfs0
ninforge list ./game.xci --json
ninforge extract ./game.xci root/secure/example.nca ./example.nca
ninforge nacp info ./control.nacp --json
ninforge info ./main.nso --json
ninforge verify ./game.nsp
ninforge extract ./game.nsp some-file.nca ./some-file.nca
ninforge list ./game.nds
ninforge extract ./game.nds arm9.bin ./arm9.bin
ninforge list ./game.nds --json
ninforge extract ./game.nds nitrofs/sound/bgm.bin ./bgm.bin
ninforge scan /drive/games --json
ninforge saves scan /drive/saves --json
ninforge saves backup /drive/saves/example.sav /drive/backups/example.sav
```

- `info` reads bounded header, PFS0 directory and DS FNT/FAT structures; it does not read an entire game image into memory. It uses signatures and sanity checks rather than trusting filename extensions.
- `info ./main.nso` reports the readable NSO module build ID (64 hex characters) and the derived 16-hex-character Atmosphère cheat build ID (first eight bytes). This is **not** a title ID and cannot by itself identify a game or decrypt an NCA.
- `nacp info` reads a separately obtained, unencrypted 0x4000-byte control.nacp and exposes localized titles, publishers, display version and selected ID fields. NACP has no unique signature, so inspection is **explicit**; compressed title tables introduced in newer firmware are rejected until supported.
- `list` enumerates PFS0/HFS0/XCI entries or header-defined DS regions (ARM9/ARM7, FNT/FAT, overlay tables). DS header section labels are synthetic; separate `nitrofs/` entries are the actual DS filesystem paths. PFS0 is an outer archive format; encrypted NCA contents are **not** decrypted.
- `verify` validates PFS0/HFS0/XCI entry names and structural bounds, or DS section and NitroFS file bounds. HFS0 SHA-256 hashes are not verified. It is **not** a content hash check, signature check, or authenticity guarantee.
- `extract` writes **one specified** PFS0/HFS0/XCI entry, DS section or NitroFS file to an **explicit** output path, refuses to overwrite existing output and never builds paths from archive filenames. Extracted outputs stay outside the repository.
- `scan <directory>` recursively inventories recognized game files, skips symlinks and streams file reports; `scan --json` uses NDJSON (one object per line), reports bad files to stderr and exits nonzero on errors.
- `saves scan` discovers potential raw saves using extension hints, without claiming game compatibility or inspecting personal saves. `saves backup` copies an explicitly selected regular file to a named output; it never overwrites, publishes via a hard link after syncing a temporary copy, and leaves the source untouched. The destination filesystem must support hard links.
- `--json` on `info` and `list` yields a stable initial machine-readable shape for integration with tools such as Cheatarium.

## Architecture

- `src/lib.rs`: format identification, metadata, bounded PFS0 directory parsing, streaming extraction.
- `src/hfs0.rs`: bounded standalone HFS0 and XCI partition indexing.
- `src/nacp.rs`: standalone NACP metadata inspection; no decryption or game file extraction.
- `src/nds.rs`: header-declared DS regions and bounded FNT/FAT NitroFS traversal.
- `src/saves.rs`: generic save candidate inventory and no-overwrite, file-by-file backup; no save editing or credentials.
- `src/main.rs`: thin CLI presentation layer; no format-specific data logic.
- Console modules will be separated as their parsers grow. Share generic IO/bounds utilities but **do not** impose a fake common save format.
- Preserve a read-only default. Any future save editor requires format-aware validation, an explicit backup, and atomic replace/rollback.
- External backends such as hactool/NSTool may be opt-in fallbacks later. Prefer native Rust implementations where feasible; no external tool is required for current functionality.

See [roadmap](docs/ROADMAP.md), [format support](docs/FORMATS.md), and [test/data rules](docs/TESTING.md).

## Scope and legal/data boundaries

Ninforge is meant for interoperable inspection, preservation, and backups of files you are entitled to use. **Never commit commercial ROMs, full game dumps, proprietary keys, tickets, user saves, or copyrighted game assets.** Gitignore and CI block common filenames, but contributors must also review all staged files. Optional tiny, freely distributable homebrew/test ROMs may be introduced **only with explicit redistribution permission, a clear license/source attribution, and a narrowly scoped testing purpose**; synthetic in-memory fixtures are preferred. Nothing in the repo provides decryption keys or facilitates acquiring games.

MIT licensed; see [LICENSE](LICENSE).
