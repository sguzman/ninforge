# Wii U WUX inspection

Ninforge recognizes the **WUX0** deduplicated-sector container and distinguishes inexpensive geometry inspection from opt-in validation of every sector-table reference.

The 32-byte little-endian header contains the `WUX0` magic, a second fixed marker (`0x1099D02E`), the sector size, an uncompressed-size claim, and flags. After the header is a little-endian 32-bit index for each logical sector. The stored-sector array begins at the next sector-size-aligned position. Multiple logical sectors may deliberately point to the same stored sector.

- `ninforge info game.wux --json` validates header/table/sector-array byte extents **without traversing the index**.
- `ninforge wiiu wux-check game.wux --json` streams all indices, checks every referenced physical sector against available stored sectors, and reports deduplicated-reference counts.
- `ninforge verify game.wux` performs the same stronger index validation.

Both operations are **read-only**. They do not reconstruct WUD, extract partition files, decrypt title content, authenticate the source image, or verify hashes. WUD raw-image recognition and encrypted partition handling are **not implemented**. File extensions alone never establish recognition. The parser caps index size and supported sector geometry, so unusual but valid variants may need a later explicit adapter.

References for the published layout:
- [Cemu WUX header and read algorithm](https://github.com/kreinholz/Cemu-upstream/blob/main/src/Cafe/Filesystem/WUD/wud.cpp)
- [Cemu WUX type declaration](https://github.com/kreinholz/Cemu-upstream/blob/main/src/Cafe/Filesystem/WUD/wud.h)
- [Independent WUX format overview](https://pkg.go.dev/github.com/bodgit/wud/wux)

Synthetic fixtures in `tests/wux_cli.rs` are constructed in memory and are not redistributed Wii U media.
