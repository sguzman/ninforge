# Ninforge

A **Rust-first, reusable CLI + library** for inspecting Nintendo game files, containers, and (later) saves across Nintendo console generations. Linux/EndeavourOS is the primary development target; the code should remain portable. No web app, daemon, or mandatory emulator dependency.

**Current status: early, read-only format inspection.** The working implementation detects signatures for Switch NSP/PFS0, XCI, readable NCA headers, 3DS NCSD, DS, Wii, GameCube, GBA, GB/GBC, N64, and NES. Only NSP/PFS0 supports internal file listing, bounded single-entry extraction and structural verification. Signature recognition **does not** mean full parsing or decryption support. Titles/IDs requiring encrypted control metadata or game-specific save schemas are not yet available.

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
ninforge verify ./game.nsp
ninforge extract ./game.nsp some-file.nca ./some-file.nca
```

- `info` reads only small header ranges except the bounded PFS0 directory. It uses signatures and sanity checks rather than trusting filename extensions.
- `list` enumerates the internal PFS0 file names, sizes and offsets. PFS0 is an outer archive format; encrypted NCA contents are **not** decrypted.
- `verify` validates PFS0 table structure, offsets and bounds. It is **not** a content hash check, signature check, or authenticity guarantee.
- `extract` writes **one specified** PFS0 entry to an **explicit** output path, refuses to overwrite existing output and never builds paths from archive filenames. Extracted outputs stay outside the repository.
- `--json` yields a stable initial machine-readable shape for integration with tools such as Cheatarium.

## Architecture

- `src/lib.rs`: format identification, metadata, bounded PFS0 directory parsing, streaming extraction.
- `src/main.rs`: thin CLI presentation layer; no format-specific data logic.
- Console modules will be separated as their parsers grow. Share generic IO/bounds utilities but **do not** impose a fake common save format.
- Preserve a read-only default. Any future save editor requires format-aware validation, an explicit backup, and atomic replace/rollback.
- External backends such as hactool/NSTool may be opt-in fallbacks later. Prefer native Rust implementations where feasible; no external tool is required for current functionality.

See [roadmap](docs/ROADMAP.md), [format support](docs/FORMATS.md), and [test/data rules](docs/TESTING.md).

## Scope and legal/data boundaries

Ninforge is meant for interoperable inspection, preservation, and backups of files you are entitled to use. **Never commit commercial ROMs, full game dumps, proprietary keys, tickets, user saves, or copyrighted game assets.** Gitignore and CI block common filenames, but contributors must also review all staged files. Optional tiny, freely distributable homebrew/test ROMs may be introduced **only with explicit redistribution permission, a clear license/source attribution, and a narrowly scoped testing purpose**; synthetic in-memory fixtures are preferred. Nothing in the repo provides decryption keys or facilitates acquiring games.

MIT licensed; see [LICENSE](LICENSE).
