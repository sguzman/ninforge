# Format capability matrix

| Family | Recognition method | Header metadata | List contents | Extraction | Full integrity verify |
|---|---|---|---|---|---|
| Switch NSP (PFS0) | `PFS0` magic | Entry count | Yes | One entry | No; names, non-overlap and bounds only |
| Switch HFS0 | `HFS0` signature | Entry count | Yes | One entry | No; structural checks only |
| Switch XCI | `HEAD` at 0x100 | Root partition offset and entry count | Root and nested HFS0 partitions | One entry | No; structural checks only |
| Switch package audit | Explicit NSP + plaintext CNMT | Claimed title/version and per-content ID/size cross-check | Referenced NCA names with status | No | No; filenames and lengths only |
| Switch CNMT | Explicit plaintext file | Title ID, version, linked NCA content IDs/sizes | References only | No | No; digest not checked |
| Switch NSO | `NSO0` header | Full module build ID and Atmosphère short cheat build ID | No | No | No; header only |
| Switch NACP | Explicit command (no magic) | Localized titles, publishers, display version and IDs | No | No | No; metadata parser only |
| Switch NCA | Readable `NCA2`/`NCA3` at 0x200 | Format/length only | No | No | No |
| 3DS cartridge | `NCSD` at 0x100 | Format/length only | No | No | No |
| DS | Expected logo CRC + game code | Title, game/maker/unit/version codes and section count | Header sections and NitroFS files | One section or NitroFS file | No; bounded sections, directory/FAT/file checks |
| Wii disc | Disc magic + ID | Game ID | No | No | No |
| GameCube disc | Disc magic + ID | Game ID and title | No | No | No |
| GBA | Fixed header byte, game code, complement checksum | Title, game/maker code, version | No | No | No |
| GB/GBC | Nintendo logo and header checksum | Title, cartridge/size codes | No | No | No |
| N64 | Three standard byte-order magics | Byte order | No | No | No |
| NES | iNES signature | Header type, basic sizes, mapper (iNES only) | No | No | No |
| CIA / SNES / Wii U / Switch 2 | Not yet implemented | No | No | No | No |

## Notes

- File extensions are not used to claim format support; an unknown header remains Unknown even if named `.nsp`.
- An NSP is a PFS0 outer container. `info` cannot report a reliably decrypted title ID, display name, build ID, or game version yet.
- NES 2.0 is identified but extended sizes and mapper fields are **not** interpreted as iNES.
- GBA/GB header checksum verification is only a recognition heuristic. `verify` is currently available for PFS0 and DS structures only.
- XCI, NCA and 3DS signature detection may not recognize encrypted or differently laid out variants.
- DS regions are header sections, not the cartridge filesystem; header CRC is not checked yet.
- `scan --json` outputs NDJSON and skips symlinks; malformed files cause a nonzero exit.
- All extraction happens with explicit output paths and streams data without buffering full game files.
