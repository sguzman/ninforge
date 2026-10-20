# Format capability matrix

| Family | Recognition method | Header metadata | List contents | Extraction | Full integrity verify |
|---|---|---|---|---|---|
| Switch NSP (PFS0) | `PFS0` magic | Entry count | Yes | One entry | No; names, non-overlap and bounds only |
| Switch HFS0 | `HFS0` signature | Entry count | Yes | One entry | No; structural checks only |
| Switch XCI | `HEAD` at 0x100 | Root partition offset and entry count | Root and nested HFS0 partitions | One entry | No; structural checks only |
| Switch package audit | NSP/PFS0 or XCI `root/secure` + plaintext CNMT; optional NACP/NSO and `--hash` | Claimed title/version and content references; external title/build data tagged unverified | Referenced NCA names and SHA-256 comparison status | No | Optional full NCA SHA-256 and plaintext NCA header structural comparisons against supplied unverified CNMT; not authenticity validation |
| Switch CNMT | Explicit plaintext file | Title ID, version, linked NCA content IDs/sizes | References only | No | No; digest not checked |
| Switch NSO | `NSO0` header | Full module build ID and Atmosphère short cheat build ID | No | No | No; header only |
| Switch NACP | Explicit command (no magic) | Localized titles, publishers, display version and IDs | No | No | No; metadata parser only |
| Switch NCA | Readable `NCA2`/`NCA3` at 0x200 | Format/length only | No | No | No |
| 3DS standalone NCCH | `NCCH` at 0x100 | Program/partition IDs, product code, crypto flags, media-unit size | `3ds ncch-regions` lists bounded ExeFS/RomFS/etc. spans | No | Structural only, no RSA signature/content hash/decryption |
| 3DS cartridge NCSD | `NCSD` at 0x100 | Media ID, declared size, media unit and type flags, partition count | `3ds partitions` shows up to 8 bounded NCCH spans | No | Explicit structural bounds only; no RSA signature/decryption or NCCH hash checks |
| DS save wrappers | User-directed `nds save info`; DeSmuME footer, No$GBA header or original Action Replay DS `ARDS0001` wrapper | Known wrapper fields, compression flag, saved-size hints | No game-file listing | No | Bounds checks only; no save-content authenticity or chip identification |
| DS | Expected logo CRC field + game code | Title, game/maker/unit/version codes, computed logo/header CRCs and optional multilingual banner title/CRC | Header sections, NitroFS files and banner.bin | One section, NitroFS file or banner | CRC-16 logo/header and optional banner checks; not signatures or full ROM hashing |
| Wii disc ISO | Disc magic + ID | Game ID, title, disc version, region, four partition group counts | Partition addresses via `wii partitions`; metadata/data extent checks via `wii partition-check` | No | Table/address bounds with optional partition header metadata span checks, not decryption or hashes |
| Wii WBFS | WBFS superblock signature | Host/virtual sector sizes, declared volume capacity and slot count | Slot count via `info`; mapped disc records via `wii wbfs-check` | No | Opt-in metadata/physical-block bounds checks; not encrypted game data/hashes |
| GameCube disc | Disc magic + ID | Game ID and title | No | No | No |
| GBA | Fixed 0x96 byte + plausible game code (checksum can be damaged) | Title, maker/game codes, version, unit/debug flags, complement and weak logo sum | No | No | Header-only complement plus weak logo sum, not exact bitmap/full-ROM validation |
| GB/GBC | Cartridge logo (header checksum may be damaged) | Title, CGB/SGB flags, mapper, ROM/RAM capacity codes, licensee, header checksum | No | No | Explicit `verify` streams the ROM to check declared file size, header checksum and additive global checksum (not cryptographic) |
| N64 | Three standard byte-order magics | Byte order | No | No | No |
| NES | iNES signature | Header type, basic sizes, mapper (iNES only) | No | No | No |
| CIA / SNES / Wii U / Switch 2 | Not yet implemented | No | No | No | No |

## Notes

- File extensions are not used to claim format support; an unknown header remains Unknown even if named `.nsp`.
- An NSP is a PFS0 outer container. `info` cannot report a reliably decrypted title ID, display name, build ID, or game version yet.
- NES 2.0 is identified but extended sizes and mapper fields are **not** interpreted as iNES.
- GBA `info` separately reports checksum status; `verify` checks only the 0xC0-byte header (there is no standard global ROM checksum or declared ROM capacity). GB/GBC `verify` checks full length and a global additive checksum. An invalid global checksum is an explicit verification failure but not proof of tampering or non-authenticity.
- Wii ISO partition table pointers use 4-byte words, not byte offsets. Table parsing caps counts, checks duplicate addresses and never treats a partition offset as a content length. WBFS parsing does not reconstruct or decrypt the filesystem.
- XCI, NCA and 3DS signature detection may not recognize encrypted or differently laid out variants.
- DS regions include header sections and NitroFS; DS header/logo and optional banner CRCs are checked when `verify` is requested.
- `scan --json` outputs NDJSON and skips symlinks; malformed files cause a nonzero exit.
- All extraction happens with explicit output paths and streams data without buffering full game files.
