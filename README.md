# Ninforge

A **Rust-first, reusable CLI + library** for inspecting Nintendo game files, containers, and save backups across Nintendo console generations. Linux/EndeavourOS is the primary development target; the code should remain portable. No web app, daemon, or mandatory emulator dependency. Ninforge is a standalone Nintendo-format toolkit: it does not import, target, or control any separate application.

**Current status: early format inspection and safe single-file save backups.** The working implementation detects signatures for Switch NSP/PFS0, XCI, readable NCA headers, 3DS NCSD, DS, Wii, GameCube, GBA, GB/GBC, N64, and NES. NSP/PFS0 and HFS0 support bounded entry inspection and extraction. XCI reads the root partition and one nested HFS0 level. DS supports ROM header sections, NitroFS files and localized cartridge banner titles, including read-only banner extraction and CRC-16 checks of the logo, header and optional banner. GB/GBC additionally decodes mapper and capacity codes and supports full-ROM additive checksum verification. Both perform structural, not cryptographic, verification. Signature recognition **does not** mean full parsing or decryption support. Titles/IDs requiring encrypted control metadata or game-specific save schemas are not yet available.

## Build

Requires Rust 1.82+ (`rustup`/Cargo) and Git. The CLI is standalone at runtime; Cargo resolves the pure-Rust `sha2` build dependency:

```sh
cargo build --release
cargo test --all-targets
cargo run -- help
```

For a local install: `cargo install --path .`. On EndeavourOS, use the installed Rust toolchain; no Python, Node, or shell-wrapper runtime is required.

## Usage

```sh
ninforge info ./game.nsp
ninforge snes header ./candidate.sfc --json
ninforge info ./game.nes --json
ninforge verify ./game.nes
ninforge info ./game.gba --json
ninforge info ./title.cia --json
ninforge 3ds cia-sections ./title.cia --json
ninforge 3ds cia-audit ./title.cia --json
ninforge 3ds cia-ticket ./title.cia --json
ninforge info ./game.3ds --json
ninforge 3ds partitions ./game.3ds --json
ninforge 3ds crosscheck ./game.3ds --json
ninforge info ./partition.ncch --json
ninforge 3ds ncch-regions ./partition.ncch --json
ninforge verify ./game.gba
ninforge info ./game.gbc --json
ninforge info ./game.z64 --json
ninforge verify ./game.v64
ninforge info ./game.iso --json
ninforge info ./game.wux --json
ninforge wiiu wux-check ./game.wux --json
ninforge list ./game.gcm --json
ninforge verify ./game.gcm
ninforge extract ./game.gcm assets/hello.bin ./hello.bin
ninforge wii partitions ./game.iso --json
ninforge wii partition-check ./game.iso --json
ninforge info ./game.wbfs --json
ninforge wii wbfs-check ./game.wbfs --json
ninforge verify ./game.gb
ninforge list ./game.nsp
ninforge list ./game.nsp --json
ninforge list ./game.hfs0
ninforge list ./game.xci --json
ninforge extract ./game.xci root/secure/example.nca ./example.nca
ninforge nacp info ./control.nacp --json
ninforge info ./main.nso --json
ninforge nca info ./decrypted-header.bin --json
ninforge cnmt info ./meta.cnmt --json
ninforge package audit ./game.nsp ./metadata.cnmt --json
ninforge package audit ./game.nsp ./metadata.cnmt --hash --json
ninforge package audit-dir ./game.nsp ./readable-metadata --hash --json
ninforge package audit ./game.xci ./metadata.cnmt --hash --json
ninforge titles inventory ./switch-metadata-bundles --json
ninforge titles inventory ./switch-metadata-bundles --packages --hash --headers --json
ninforge package audit-dir ./game.nsp ./readable-metadata --headers --json
ninforge package audit ./game.nsp ./metadata.cnmt --nacp ./control.nacp --main-nso ./main.nso --json
ninforge verify ./game.nds
ninforge verify ./game.nsp
ninforge extract ./game.nsp some-file.nca ./some-file.nca
ninforge list ./game.nds
ninforge info ./game.nds --json
ninforge extract ./game.nds banner.bin ./banner.bin
ninforge extract ./game.nds arm9.bin ./arm9.bin
ninforge list ./game.nds --json
ninforge extract ./game.nds nitrofs/sound/bgm.bin ./bgm.bin
ninforge scan /drive/games --json
ninforge nds save info /drive/saves/example.dsv --json
ninforge nds save info /drive/saves/backup.duc --json
ninforge nds save info /drive/saves/example.sav
ninforge saves scan /drive/saves --json
ninforge saves backup /drive/saves/example.sav /drive/backups/example.sav
```

- Nintendo DS `info` also reports separately calculated logo CRC-16 (`0xC0..0x15B`) and cartridge header CRC-16 (`0x00..0x15D`) and their stored values. `verify game.nds` requires both to match; if a banner is present, its applicable banner CRCs must match as well. An invalid checksum is shown in `info` rather than concealed, while `verify` exits unsuccessfully. These CRCs are corruption checks, not Nintendo signatures or proof of authentic software.
- Nintendo DS `info` also reports header-referenced banner version, size, up to eight localized UTF-16 titles, and CRC-16 checks for supported DS/DSi versions (1, 2, 3, 0x0103). `list` exposes `banner.bin` only when present; `extract` can copy it to an explicit destination without overwriting. A CRC failure is reported as such; it is not proof of authenticity or a structural error by itself.
- `nds save info <file> [--json]` recognizes DeSmuME DSV (40-byte footer and cookie), No$GBA SRAM wrappers (signature, compression marker, and bounded size fields), and original Action Replay DS exports (`ARDS0001` signature and a 500-byte wrapper) regardless of filename extension. It reads only a small header/footer, never decompresses or changes a save, and does not guess the title, save chip or actual capacity from a raw file. Files without a supported signature are labeled `raw_or_unidentified`; familiar raw byte lengths are flagged only as non-authoritative hints. Game association is always unverified.
- Wii U WUX `info` validates the header and sector-array geometry without reading the deduplication index. `wiiu wux-check` and `verify` explicitly stream and bounds-check all sector indices, but do not decrypt, reconstruct, or authenticate WUD contents. Raw WUD inspection remains pending; see [Wii U format notes](docs/WII_U.md).
- GameCube `info` parses the bounded GCM/ISO filesystem table, validates directory hierarchy and file byte extents, and reports the main DOL/FST pointers; `list` resolves nested paths and `extract` copies one explicitly named file to an explicit new destination. Unsafe, duplicate, malformed, non-UTF-8 or oversized names are rejected rather than guessed. This is structural inspection only: executable sections, disc authenticity, hashes, and file contents are not verified.
- Wii `info` reads the raw ISO's four partition groups (big-endian 4-byte-word pointers) and the optional region setting; `wii partitions <iso> --json` lists each group's partition type and absolute byte offset. These are **not extractable files**: partition extents, encryption, tickets, signatures and content hashes are not verified. `verify` checks partition-table address bounds only; explicit `wii partition-check <iso> [--json]` additionally reads the 28-byte ticket-adjacent offset/size fields per partition, validating the TMD/certificate/H3/data byte ranges and rejecting malformed or overlapping metadata ranges. It does not parse signed metadata, check hashes, decrypt or alter data. WBFS `info` recognizes the superblock, sector parameters and occupied disc-slot entries without decoding the disc block map or reconstructing a Wii ISO. `verify` for WBFS checks only those same header fields. WBFS containers are **not** accepted by `wii partitions`. For an explicit, deeper but still read-only inspection, `wii wbfs-check <file> [--json]` examines occupied disc-header copies and all block-address entries. It checks the fixed dual-layer-sized logical mapping table, record location/size, disc magic/ID, duplicate physical indices, declared-volume bounds and actual-file bounds. It does **not** decrypt, reconstruct the disc, read mapped game bytes, verify hashes or infer the game title from a filename. Sparse/truncated files whose mapped physical blocks extend beyond the supplied image fail this strict check.
- 3DS `crosscheck <ncsd> [--json]` checks that each declared NCCH-type partition has a readable NCCH header and that the inner declared size fits its outer NCSD partition. For nonzero partition IDs, the command reports whether NCSD/NCCH ID claims agree, including mismatches. A zero outer ID yields `null` rather than a fabricated match. No RSA signature, encrypted content, hash or authentic title relationship is verified.
- 3DS `cia-ticket <file> [--json]` compares the v1 ticket's declared title ID/version to the TMD title ID/version. Title IDs may disagree (reported explicitly) and versions can legitimately differ; neither case is interpreted as cryptographic proof of authenticity or forgery. The encrypted titlekey, signatures and certificate chains are not exposed or verified.
- 3DS `cia-audit <file> [--json]` interprets the embedded TMD's recognized signature *type*, title ID/version, and up to 4096 content-chunk records. It compares selected content indices to the CIA content bitmap and checks that the raw sizes of selected records do not exceed the archive's content section. Absent optional content is reported rather than rejected; extra CIA bitmap selections remain visible as unmatched. Cryptographic hashes and signatures are **not verified**, nor is payload decryption or titlekey use attempted.
- 3DS CIA `info` uses a conservative header heuristic and checks its 64-byte-aligned certificate, ticket, TMD, content, and optional meta section bounds. `3ds cia-sections <file> [--json]` additionally lists exact section positions and counts bits in the 0x2000-byte content-index bitmap. It does not decode the TMD's content-chunk records, decrypt files, or verify a ticket, hash, or signature. A bitmap count is not authentication or proof that embedded contents match the TMD.
- Standalone 3DS NCCH `info` reads the declared program/partition IDs, product code, media-unit size, crypto flags, and bounded optional exheader, plaintext/logo, ExeFS and RomFS byte spans. `3ds ncch-regions <file> [--json]` lists those regions; encrypted content, RSA signatures and hashes are **not verified**, even when the NCCH flag claims no encryption. This command does not automatically associate an NCCH with a containing NCSD.
- 3DS NCSD/CCI `info` decodes declared media capacity, media unit size, media ID, card media-type claim, and partition count. `3ds partitions <file> [--json]` describes up to eight partition byte spans, filesystem types, crypt-type flags and partition IDs; it rejects out-of-file, out-of-capacity and overlapping ranges. `verify` checks **only** those same structural bounds: RSA header signatures, NCCH encryption, title identities and partition hashes remain unverified. No files are extracted or modified.
- SNES `snes header <file> [--json]` examines LoROM, HiROM, and ExHiROM internal-header candidates at the normal locations and optionally 512 bytes later (copier prefix). Because SNES has no universal leading signature, `info` does not automatically classify arbitrary input as SNES. A candidate score draws on header location, map-mode, complement/checksum pair, title, reset vector and declared capacity. Tied candidates remain explicitly ambiguous; no entire-ROM checksum, mapper authenticity or title ownership is claimed. The command is read-only and does not strip copier prefixes.
- Nintendo 64 `info` normalizes all three recognized ROM byte orders (.z64 native, .v64 swapped pairs, and .n64 little-endian words) before reporting game title/code, country and version, entry point, SDK word, and stored CRC1/CRC2. Detection is based on bytes rather than filename. Unprintable title fields are sanitized. `verify` confirms only the recognized 64-byte header and explicitly does **not** validate CIC-dependent boot checksums or the ROM data.
- NES/iNES/NES 2.0 `info` decodes mapper/submapper, PRG/CHR ROM capacities, trainer, battery and mirroring, and NES 2.0 RAM/NVRAM shift fields. For old iNES dumps with polluted header padding, high mapper bits are marked ambiguous instead of trusted. `verify game.nes` bounds-checks declared trainer/PRG/CHR file regions and rejects unexplained trailing bytes in NES 2.0 without a miscellaneous ROM declaration. It does not hash ROM contents or prove the header's mapper claim.
- GBA `info` reports the mandatory fixed header byte, complement checksum (covering `0xA0..0xBC`), debug/unit fields, reserved-byte status, and a **weak** additive diagnostic over the logo area. `verify game.gba` checks the header complement and that weak sum, not the Nintendo logo bitmap, game-data integrity, signed provenance, cartridge capacity or backup-chip type. A damaged complement remains inspectable by `info`; `verify` fails explicitly.
- GB/GBC `info` decodes cartridge mapper, CGB/SGB mode, destination, licensee, ROM/RAM size codes and header-checksum status without reading the entire game. An invalid header checksum remains inspectable. `verify <game.gb>` strictly streams and checks the header checksum, declared ROM byte length, and global additive checksum (the global checksum is not cryptographic and some ROMs deliberately contain mismatches). Unknown or historically ambiguous ROM/RAM codes remain explicit rather than guessed. Header recognition still requires the fixed cartridge logo sequence; it is not a guarantee that a ROM will run on hardware.
- `info` reads bounded header, PFS0 directory and DS FNT/FAT structures; it does not read an entire game image into memory. It uses signatures and sanity checks rather than trusting filename extensions.
- `nca info` accepts an explicitly supplied readable/decrypted NCA2 or NCA3 header (or full archive with plaintext header). Reports content type, program ID, distribution, rights ID when present and bounded filesystem section layout. Raw retail NCA headers remain encrypted; Ninforge does not decrypt them.
- `titles inventory <root> --packages --json` optionally checks a **deliberately named** `package.nsp` or `package.xci` file in each immediate metadata bundle against that bundle's plaintext CNMT. Only one can be present; multiple candidate packages or package symlinks are errors. A missing designated package remains metadata-only, not a failure. `--hash` streams SHA-256 and `--headers` checks readable NCA headers; both require `--packages` and are never run by default. The JSON embeds the original per-content package audit, including absent/mismatched files and hash status. Even exact digest matching establishes only agreement with the **unverified supplied CNMT**, not publisher authentication or executable-to-title linkage. Do not copy full game archives into the public Git repository.
- `titles inventory <root> --json` reads one metadata bundle per immediate child directory. Each bundle must contain exactly one plaintext `*.cnmt`, and can include a `*.nacp` plus a user-designated `main.nso`. It groups base applications, patches and add-on content using **claimed CNMT application references**, retains numeric CNMT versions separately from NACP display versions, and reports the highest supplied base/patch revision (not the latest published version). Identical and conflicting duplicate title/version records are surfaced; no candidate is silently preferred. No recursion, symlink following or decryption. The JSON includes optional NSO build IDs and never claims title-to-executable authentication.
- `package audit-dir <nsp-or-xci> <metadata-dir>` searches only the selected directory for exactly one plaintext `*.cnmt`, at most one `*.nacp`, and an optional file explicitly named `main.nso`. Multiple CNMT/NACP candidates or symlinks are errors; other NSO modules are never guessed to be the main executable. Its output uses the existing package audit schema, with metadata still marked as unverified external evidence. Add `--hash` to check NSP bytes against CNMT assertions.
- `package audit <nsp-or-xci> <cnmt> --headers` reads up to 0x400 header bytes from each uniquely present NCA (including XCI secure-partition entries). Already-readable NCA2/NCA3 headers are checked against the CNMT-declared content type and size; inaccessible encrypted headers are explicitly marked unavailable. NCA program IDs are reported but **not equated to CNMT title IDs**. This is a structural consistency check only, not content authentication. Combine with `--hash` for full-file SHA-256 against the independently supplied CNMT digest.
- `package audit <nsp-or-xci> <cnmt> --hash` streams SHA-256 over size-matched NCA entries inside the NSP and compares each hash with the content digest asserted by the supplied CNMT. Hashes are calculated only on request, in bounded memory, and no output or temporary game file is created. Per-record statuses distinguish `matched`, `mismatched`, `unavailable`, and `not_checked`. A match **does not prove the CNMT is genuine**. `hashes_verified` remains false in the JSON to avoid confusing content correlation with signature/title authentication; `hashes_match_supplied_cnmt` reports the narrower claim.
- `package audit <nsp-or-xci> <cnmt>` joins PFS0 file names and lengths to a **separately supplied, plaintext CNMT**. Add optional `--nacp <file>` for localized title/publisher/display version and `--main-nso <file>` for an explicitly user-designated NSO build ID. Both remain marked as **unverified external evidence**: supplying files together does not prove they belong to the same game, and a CNMT numeric version is not the NACP display version. It reports present, missing, size mismatches, ambiguous case collisions and unsupported compressed NCZ candidates. It does not decrypt the NSP, verify content hashes, or establish the CNMT's provenance. JSON output is intended for general-purpose metadata tooling.
- `cnmt info` inspects a standalone plaintext CNMT for title ID, update version, referenced content IDs/sizes and related title metadata. Content IDs reference external NCAs rather than embedded bytes. Hashes are not verified.
- `info ./main.nso` reports the readable NSO module build ID (64 hex characters) and the derived 16-hex-character Atmosphère cheat build ID (first eight bytes). This is **not** a title ID and cannot by itself identify a game or decrypt an NCA.
- `nacp info` reads a separately obtained, unencrypted 0x4000-byte control.nacp and exposes localized titles, publishers, display version and selected ID fields. NACP has no unique signature, so inspection is **explicit**; compressed title tables introduced in newer firmware are rejected until supported.
- `list` enumerates PFS0/HFS0/XCI entries or header-defined DS regions (ARM9/ARM7, FNT/FAT, overlay tables). DS header section labels are synthetic; separate `nitrofs/` entries are the actual DS filesystem paths. PFS0 is an outer archive format; encrypted NCA contents are **not** decrypted.
- `verify` validates PFS0/HFS0/XCI entry names and structural bounds, or DS section and NitroFS file bounds. HFS0 SHA-256 hashes are not verified. It is **not** a content hash check, signature check, or authenticity guarantee.
- `extract` writes **one specified** PFS0/HFS0/XCI entry, DS section or NitroFS file to an **explicit** output path, refuses to overwrite existing output and never builds paths from archive filenames. Extracted outputs stay outside the repository.
- `scan <directory>` recursively inventories recognized game files, skips symlinks and streams file reports; `scan --json` uses NDJSON (one object per line), reports bad files to stderr and exits nonzero on errors.
- `saves scan` discovers potential raw saves using extension hints, without claiming game compatibility or inspecting personal saves. `saves backup` copies an explicitly selected regular file to a named output; it never overwrites, publishes via a hard link after syncing a temporary copy, and leaves the source untouched. The destination filesystem must support hard links.
- SHA-256 checks depend on a pure-Rust cryptographic crate (`sha2`) and operate on raw encrypted NCA bytes without decrypting them.
- `--json` on `info` and `list` yields a stable initial machine-readable shape for integration with other tools.

## Architecture

- `src/lib.rs`: format identification, metadata, bounded PFS0 directory parsing, streaming extraction.
- `src/hfs0.rs`: bounded standalone HFS0 and XCI partition indexing.
- `src/nacp.rs`: standalone NACP metadata inspection; no decryption or game file extraction.
- `src/nca.rs`: decrypted NCA header reader with checked section bounds.
- `src/cnmt.rs`: standalone CNMT metadata and typed content references.
- `src/title_inventory.rs`: bounded, version-aware multi-bundle CNMT inventory with deterministic grouping and duplicate/conflict checks.
- `src/metadata_dir.rs`: non-recursive, fail-closed discovery of separately accessible metadata sidecars.
- `src/package.rs`: read-only NSP/XCI secure-partition correlation with plaintext CNMT, optional streaming SHA-256 checks, and explicit external metadata evidence.
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
