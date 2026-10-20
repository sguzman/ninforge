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

## PFS0 filename safety regression

As in the HFS0 parser, PFS0 rejects slash/backslash path separators, the `.` and `..` entries and control characters before exposing an archive entry for listing or extraction. Synthetic tests cover malicious names and a legitimate dotted basename, without requiring a real ROM. All writes still require an explicit destination chosen by the caller.

## Nintendo DS/DSi cartridge banners

Version 1/2/3/0x0103 banners are constructed entirely from synthetic data, referenced through the DS ROM header offset 0x68, and read with a fixed maximum of 0x23c0 bytes. Unit tests cover little-endian version size, languages, UTF-16 titles, CRC-16/IBM reference vector, all applicable per-version CRC regions, intentionally corrupted CRC (reported rather than accepted), absent banner, invalid offset/version/truncation, malformed UTF-16 and control characters. CLI integration tests verify `info`/`list --json` metadata, `banner.bin` extraction without clobbering, and safe errors. Icons are not rendered and CRCs are not cryptographic signatures.

## Nintendo DS header integrity

Nintendo DS header CRC uses CRC-16/IBM reflected 0xA001 with initial value 0xFFFF. Logo CRC covers `0xC0..0x15C`, stored at `0x15C`; the overall header CRC covers `0x00..0x15E`, stored at `0x15E`. The CRC implementation is shared with DS banner inspection and checked against the standard `123456789` vector (`0x4B37`). A purely synthetic zero-filled logo with an independently calculated two-byte suffix reaches the required `0xCF56` CRC without embedding Nintendo logo artwork. Library tests and black-box CLI tests cover independent logo/header failures, valid fixtures, truncated input, and corrupt banner CRC. `info` reports mismatches, whereas `verify` treats mismatches as failures; CRCs are not cryptographic authentication or a promise of full-ROM integrity.

## Nintendo DS save wrapper identification

The `nds save info` command reads only a bounded prefix and final 40-byte DSV footer; it never streams or rewrites entire saves. Synthetic tests identify the documented DeSmuME 16-byte `|-DESMUME SAVE-|` footer cookie and No$GBA `NocashGbaBackupMediaSavDataFile` plus `SRAM` header fields. Negative cases cover truncated or contradictory DSV footer data, unknown footer version, malformed No$GBA marker/compression/length, and non-signature raw byte lengths. Original Action Replay DS exports are identified only by the `ARDS0001` signature and a complete 500-byte wrapper followed by a nonempty bounded save payload; the metadata inside that wrapper is not interpreted as an authenticated game ID. Synthetic tests cover valid and truncated wrappers, filename-independent CLI output and immutable input bytes. CLI integration tests verify JSON/text fields, extension-independent identification, clean errors, and source-byte immutability. No title, cartridge, device model, or save-chip type is inferred. Reference: [DeSmuME official dsv.txt](https://github.com/TASEmulators/desmume/blob/master/desmume/doc/dsv.txt); [No$GBA header reference](https://github.com/DarkMatterCore/ndssc/blob/master/ndssc.c).

Action Replay DS source references: [DS save container description](https://github.com/DissentKindly/HMDS-GBA-Enabler/blob/main/hmds_gba_connectivity_writeup.md) and [Action Replay exporter discussion](https://gbatemp.net/threads/online-savegame-converter-1-0-alpha.48582/). Later Action Replay DSi variants are not assumed equivalent to `ARDS0001`.

## Game Boy / Game Boy Color cartridge verification

The GB/GBC header reader decodes the CGB flag, Super Game Boy flag, supported mapper codes, declared ROM size, and external RAM size using [Pan Docs cartridge header](https://gbdev.io/pandocs/The_Cartridge_Header.html). Header recognition requires the standard logo but does not require a good header checksum; a corrupted ROM remains inspectable. Synthetic tests verify 32 KiB and 64 KiB capacities, MBC3 and MBC2 metadata, legacy/special ROM-size codes, ambiguous RAM code 0x01 (unknown), invalid checksums and unknown sizes. The strict `verify` path streams the file in bounded 64 KiB chunks, requires an exact declared size, checks the 8-bit header complement and compares the big-endian global checksum while excluding bytes 0x14E..0x14F. The global checksum is only a weak additive check and can be intentionally invalid in otherwise functioning cartridges. End-to-end CLI fixtures use only synthetic ROM bytes and assert read-only behavior.

## Wii ISO and WBFS structural inspection

Synthetic ISO headers and sparse partition group tables exercise the 0x40000 four-group index, big-endian 4-byte-word offsets, partition kinds, duplicate/overlarge counts, truncated or out-of-bounds table/payload headers and region metadata. A synthetic WBFS first sector exercises big-endian sector count, host/virtual sector shifts, occupied slot count, truncated first sectors and invalid parameters. CLI tests exercise `info`, `wii partitions --json`, and strictly structural `verify` with no extraction, no decryption and no commercial disc bytes. Neither the Wii ISO partition table nor the WBFS slot array establishes partition data lengths or cryptographic integrity. References: [WiiBrew disc layout](https://wiibrew.org/wiki/Wii_disc) and [libwbfs format structures](https://github.com/wiidev/usbloadergx/blob/enhanced/source/libs/libwbfs/libwbfs.h).

## WBFS disc records and physical block-map validation

The optional `wii wbfs-check <file> [--json]` command uses the original libwbfs fixed maximum of 286864 Wii sectors per logical disc, with a 16-bit big-endian `wlba` map following a 0x100-byte copied Wii header. The `disc_info_sz` is aligned to the host sector, and disc slot N starts at host_sector + N * disc_info_sz. Tests construct two independent synthetic records and cover 4482 logical entries per disc at a 2 MiB WBFS allocation unit, valid physical block indices, duplicate mappings across and within slots, malformed occupancy flags, occupied slots beyond metadata capacity, truncated disc records, incorrect Wii disc magic, and physical blocks extending beyond declared or actual file bounds. Fast `info` and default `verify` remain superblock-only. The free-block bitmap, game bytes, decryption, and content hashes are not inspected. Reference: [libwbfs definitions](https://github.com/wiidev/usbloadergx/blob/enhanced/source/libs/libwbfs/libwbfs.c), [WBFS layout guide](https://github.com/thethiny/wii-disc-tools/blob/master/FILE_FORMATS.md).

## Wii ISO partition header span verification

The explicit `wii partition-check <iso> [--json]` command decodes seven big-endian words beginning at each partition's ticket-adjacent offset `0x2A4`. TMD and certificate lengths are in bytes; TMD, certificate, H3 and encrypted-data offsets (and the encrypted-data length) are in 4-byte words. The fixed H3 region, if declared, is `0x18000` bytes. The opt-in check validates ranges, rejects impossible sizes, overlap among declared metadata ranges, and data extending outside the supplied ISO without reading or authenticating the contents. Unit and CLI tests use synthetic Wii disc images and verify that default `info` stays structural-only. Reference: [WiiBrew Wii disc partition structure](https://www.wiibrew.org/wiki/Wii_disc).

## Game Boy Advance header checks

The GBA cartridge header occupies `0x00..0xBF`. Explicit `verify` calculates its 8-bit complement from bytes `0xA0..0xBC` followed by subtracting `0x19` and compares it with stored byte `0xBD`. A **weak** `0x4B1B` additive sum over the 156-byte logo area is checked separately, without bundling the proprietary logo bitmap or claiming exact logo authentication. No GBA header field declares the full ROM byte count or save-chip type, and verification does not attempt to establish either. Tests synthesize a logo-area sequence with the correct additive sum, exercise invalid complement and changed weak logo sum independently, and show that changes beyond the header are not detectable by this command. See [GBATEK GBA cartridge header](https://mgba-emu.github.io/gbatek/) and [Cart Reader GBA checksum implementation](https://github.com/sanni/cartreader/blob/master/Cart_Reader/GBA.ino).

## 3DS NCSD partition table

A read-only NCSD parser interprets the fixed 0x200-byte signed container header, `NCSD` at `0x100`, little-endian media-unit capacity at `0x104`, media ID at `0x108`, eight FS and crypt-type bytes at `0x110` and `0x118`, eight offset/size pairs at `0x120`, partition media IDs at `0x190`, and cart-claimed media unit shift at `0x18E`. Every populated extent is bounds-checked against the declared size and actual file and checked for overlap. Synthetic unit and CLI tests exercise two independent partitions, modified media-unit sizes, truncated headers, incomplete offset/size pairs, capacity and overlap failures. These checks do not establish RSA signature validity, authenticity, NCCH decryption or content hashes. Reference: [3dbrew NCSD format](https://3dbrew.org/wiki/NCSD).

## Standalone 3DS NCCH metadata

A bounded 0x200-byte NCCH header parser reads `NCCH` at 0x100, content size in media units at 0x104, partition ID at 0x108, program ID at 0x118, product code at 0x150, extended header size at 0x180, flags at 0x188, and optional plain/logo/ExeFS/RomFS region offset/length pairs at 0x190, 0x198, 0x1A0 and 0x1B0. Populated ranges must be contained by both declared content capacity and supplied file length without overlap. Tests use entirely synthetic headers and verify metadata, independent region addressing, invalid sizes, overlapping ranges and truncated headers. The implementation neither extracts encrypted partitions nor checks signature or hash values; a no-crypto flag remains a header claim. Source: [3dbrew NCCH structure](https://3dbrew.org/wiki/NCCH).

## 3DS CIA archive bounds

A standalone CIA has no distinct four-byte magic; normal automatic recognition requires an otherwise plausible 0x2020-byte version-zero archive header with nonzero cert, ticket, TMD and content fields. Explicit `3ds cia-sections <file> [--json]` reads only the first 0x2020 bytes and bounds-checks the 64-byte-aligned certificate, ticket, title metadata, content and optional meta sections, with overflow and out-of-file checks. Synthetic tests cover optional meta, content-index bit count, truncated sections, oversized lengths and damaged header/bitmap. Content-index bitmap entries are not reconciled with TMD chunk records; signatures, hashes, and encryption are not validated. Reference: [3dbrew CIA](https://3dbrew.org/wiki/CIA).

## Opt-in NCSD/NCCH relationship checks

The `3ds crosscheck <ncsd> [--json]` command reads the NCSD 0x200-byte header and at most eight NCCH 0x200-byte embedded headers from FS type 1 partitions, without scanning encrypted game data. It checks that the embedded NCCH's declared content capacity fits the enclosing NCSD partition and reports whether a nonzero outer partition ID agrees with the inner NCCH partition ID. Missing outer IDs are reported as unknown, and disagreeing IDs remain observable rather than becoming claims about authentic titles. Synthetic tests cover matching/contradictory/missing IDs, wrong NCCH magic, invalid FS type, and an inner size exceeding the outer region. This is header consistency, not a hash, RSA signature, or decryption check. References: [3dbrew NCSD](https://3dbrew.org/wiki/NCSD), [3dbrew NCCH](https://3dbrew.org/wiki/NCCH).

## CIA TMD content-index audit

The optional `3ds cia-audit <file> [--json]` command parses only the signed TMD metadata header and a bounded maximum of 4096 big-endian 0x30-byte content chunk records. It supports recognized RSA/ECDSA signature *types* but never verifies signatures or trusts certificate chains. It reads the title ID/version and content-record indices/types/declarations, and counts which records are selected by the CIA's 0x2000-byte bitmap. Unselected optional TMD records and unmatched CIA bitmap bits are reported, not silently equated with invalid data. Selected content raw sizes are required to fit within the CIA's content section; content ciphertext, hashes, ticket titlekeys and per-content 64-byte padding are not verified. All tests use synthetic data and explicitly exercise malformed signature types, incomplete record tables, mismatched bitmap selections and oversized content claims. References: [3dbrew title metadata](https://3dbrew.org/wiki/Title_metadata) and [3dbrew CIA](https://3dbrew.org/wiki/CIA).

## CIA ticket/TMD title identifier comparison

The explicit `3ds cia-ticket <file> [--json]` command reads only bounded ticket metadata alongside the existing TMD audit. It supports a 3DS v1 ticket, determines the signature-data layout from the big-endian signature type, reads the ticket-data title ID at `0x9C` and ticket title version at `0xA6`, and compares both fields with corresponding TMD claims. Ticket title versions may legitimately differ from TMD title versions; differences are reported without a structural failure. No titlekey ciphertext is output, no titlekey is decrypted and no RSA/ECDSA signature is verified. Synthetic fixtures cover matching fields, mismatched title IDs, unsupported ticket versions, damaged signature types and contradictory ticket sizes. Source: [3dbrew Ticket](https://3dbrew.org/wiki/Ticket).

## iNES and NES 2.0 cartridge headers

The bounded `info` parser handles the standard 16-byte iNES and NES 2.0 header, 12-bit NES 2.0 mapper and 4-bit submapper, PRG/CHR ROM sizes (including exponent/multiplier encoding), separate shift-based PRG/CHR volatile/nonvolatile RAM sizes, battery/mirroring and optional 512-byte trainer. Legacy iNES headers with nonzero old-tool padding do not receive trusted high mapper bits. `verify` bounds-checks declared PRG/CHR/trainer regions and, for NES 2.0 without miscellaneous ROMs, disallows trailing bytes. No ROM checksum or hardware authenticity is inferred. Synthetic fixtures test truncation, ambiguous legacy header fields, mapper expansion, RAM shifts, exponent-mode overflow, and trailing bytes. Source: [NESdev NES 2.0](https://www.nesdev.org/wiki/NES_2.0), [NESdev iNES](https://www.nesdev.org/wiki/INES).
