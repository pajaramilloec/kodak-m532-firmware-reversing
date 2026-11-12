# Reverse Engineering the Kodak EasyShare M532 Firmware Update Format

> Status: **open / unsolved**. This is a research log, not a working hack. The camera's
> firmware image is still opaque at the time of writing. Published in the hope that
> someone with more experience in embedded Zoran/CSR "COACH" platforms, proprietary
> LZ/Huffman schemes, or JTAG/UART bring-up can pick up where this leaves off.

## TL;DR

The Kodak EasyShare M532 (2011, Service Code 9595) is built on a **Zoran/CSR "COACH"
SoC** running **MIPS32r2, little-endian**. Its firmware update package
(`M532_110.PAK`, ~20.7 MB) contains two small, fully-readable MIPS ELF binaries
(a secondary bootloader and a flash-programming tool) and three large ELF images
that make up the actual camera application — and those three are either custom
LZ/entropy-compressed or encrypted with an undocumented, proprietary scheme.

We fully mapped the file format, located the exact function that validates the
package's integrity, and confirmed — empirically, on real hardware, five separate
times — that the checksum covers the entire file with no gaps. We were **not**
able to identify the compression/hash algorithm itself, because the code that
implements it lives inside the one part of the image we can't read.

No public documentation, tooling, or prior write-up for this SoC family appears to
exist (see [Prior Art](#prior-art)). If you know this platform, please open an
issue — see [How You Can Help](#how-you-can-help).

## Table of Contents

- [Why](#why)
- [Disclaimer](#disclaimer)
- [Platform identification](#platform-identification)
- [The .PAK file format](#the-pak-file-format)
- [Locating the integrity check](#locating-the-integrity-check)
- [On-device differential testing](#on-device-differential-testing)
- [Compression schemes ruled out](#compression-schemes-ruled-out)
- [PC-side dead ends](#pc-side-dead-ends)
- [USB enumeration](#usb-enumeration)
- [Prior art](#prior-art)
- [Repo contents](#repo-contents)
- [Reproducing this](#reproducing-this)
- [How you can help](#how-you-can-help)
- [License](#license)

## Why

The M532 is a disposable-grade point-and-shoot: cheap, long discontinued, and
Kodak pulled its firmware/software downloads from its own servers around 2012.
That combination — worthless resale value, dead official support, completely
undocumented SoC — makes it a reasonable target for a no-stakes reverse
engineering exercise. Worst case, it stays a $5 paperweight it already was.

## Disclaimer

This is personal research on a personally-owned, end-of-life device, done for
educational purposes. Nothing here is intended to defeat any DRM, access control,
or copy protection on copyrighted *content* — it concerns a camera's own firmware
update mechanism. No Kodak binaries, installers, or copyrighted material are
included in this repository (see [Repo contents](#repo-contents)).

## Platform identification

Strings and symbol names recovered from the firmware package identify:

- SoC family: **Zoran "COACH"** (the string `AppGetCoachVersion` appears in the
  bootloader; Zoran's imaging SoCs were widely used in low-end 2008–2012 cameras
  under several brands)
- CPU: **MIPS32r2, little-endian, o32 ABI** (`noreorder`, confirmed via raw ELF
  headers: `EM_MIPS`, `e_flags = 0x70001001`)
- CCD sensor (not CMOS) per the official service manual
- USB: standard PTP/MTP ("Still Image" class, `USB\Class_06&SubClass_01`),
  `VID_040A` (Eastman Kodak Company's registered USB-IF vendor ID) `PID_0611`

## The .PAK file format

The firmware package (e.g. `M532_110.PAK`, firmware version `01.100000`) is a flat
binary, no wrapper container, laid out as:

```
0x000000 - 0x0001FF   512-byte header. Dense table of (address, value)-looking
                      pairs in the 0x20xx range — almost certainly an early
                      hardware bring-up table (clocks / memory controller),
                      not padding. (Confirmed: modifying any byte here still
                      trips the integrity check — see below.)

0x000200              ELF #1, "boot0": secondary-stage bootloader.
                      Fully readable MIPS32, NOT stripped — carries a symbol
                      table with ~1,074 named functions. Includes:
                        - NAND/flash section-table management
                          (BurnGetSectionsMap, BurnSectionFind, ...)
                        - NandReadElfCode / OneNandReadElfCode / LbaNandReadElfCode
                          (raw sector I/O — confirmed NOT a decompressor, see below)
                        - a USB device stack (standard descriptor/endpoint plumbing)
                        - an embedded MD5 implementation (md5_init/append/finish)
                          used by a small BurnHash* wrapper, apparently for NAND
                          write-verification during factory programming — NOT the
                          file-level checksum described below
                        - a debug-instrumented pool allocator (PoolGetEx,
                          PoolFreeEx, PoolDump, leak-detection helpers)

0x102640               ELF #2, "burn_tool": the firmware-flashing tool.
                      Also fully readable MIPS32 code, but with its symbol table
                      stripped. Contains the literal ASCII tags used by the
                      trailer format below, and the function that validates them
                      (see next section).

0x220240               ELF #3, "fw_a": first segment of the actual camera OS/app.
0x3A8138               ELF #4, "fw_b": second segment.
0x5DCDD4               ELF #5, "fw_c": third segment.
                      Combined, ~20 MB. Byte entropy is uniformly ~7.5-7.84
                      bits/byte throughout (vs. 2-6.7 for the plainly-readable
                      boot0/burn_tool code) — consistent with compression or
                      encryption. This is the part we could not break.

...$SCRIPT$ \r\n       Trailer, literal ASCII, appended with no padding before
$CHECKSUM$<4 bytes>    or after it. <4 bytes> is a raw, non-ASCII 32-bit value —
$VERSION$ \r\n         the integrity value the camera checks on upgrade.
0x01100000\r\n
```

## Locating the integrity check

`burn_tool` (ELF #2 above) contains the literal strings `$SCRIPT$`, `$CHECKSUM$`
and `$VERSION$`. Cross-referencing every `lui`/`addiu` pair in the binary that
constructs the address of the `$CHECKSUM$` string led to a function at
**vaddr `0x800d6d40`** that:

1. Walks a table of `(offset, length)` segment descriptors.
2. For each segment, calls a hashing/accumulator routine at **vaddr `0x802002a0`**.
3. Extracts the literal 4 bytes following `$CHECKSUM$` in the file trailer.
4. (Presumably) compares the two — this is the code path that produces the
   camera's `Error No. 5 — Firmware upgrade incorrect` message.

Critically, **`0x802002a0` is not inside `boot0` or `burn_tool`.** Mapping it
against the ELF program headers of the three compressed app images shows it
falls inside `fw_a`'s declared virtual address range (`0x80102380` –
`0x8037c080`), at payload-relative offset `0xFDF20`. In other words: **the actual
hashing algorithm is itself inside the one part of the firmware we can't read.**
That's the wall this project hit.

A loader-side search for an alternative path (maybe the boot-time loader
decompresses `fw_a` before jumping into it?) came up empty: `NandReadElfCode` and
its siblings in `boot0` do nothing but raw sector I/O into an allocated buffer —
no decompression call of any kind. Whatever unpacks `fw_a` at runtime, it isn't a
separate, discoverable loader routine.

## On-device differential testing

Rather than keep guessing blind, we flashed five single/minimal-byte-diff
variants of a real `M532_110.PAK` through the documented SD-card upgrade
procedure (copy to `/system/` on the card, power on with a charged battery) and
recorded the camera's own response:

| # | Modification | File size changed? | Result |
|---|---|---|---|
| 1 | Changed a 19-byte ASCII string mid-file (`"M532 Digital Camera"` → `"M532 Hacked Camera!"`, same length) | No | `Error No. 5` |
| 2 | Flipped 1 byte inside the 512-byte header's padding region | No | `Error No. 5` |
| 3 | Flipped the very first byte of the file (offset `0x0`) | No | `Error No. 5` |
| 4 | Flipped the last content byte before the `$SCRIPT$` trailer | No | `Error No. 5` |
| 5 | Appended one extra `0x00` byte after the trailer | **+1 byte** | `Error No. 5` |

Takeaways:

- The checksum covers the file **edge to edge** — no untouched header, no unused
  trailing padding, nothing we found is safe to modify.
- Test 5 suggests there's **no independent file-length check** distinct from the
  hash — consistent with the trailer being located by string search rather than
  a fixed offset/length field, so trailing garbage is silently ignored rather
  than rejected outright.

## Compression schemes ruled out

Tested against the `fw_a/b/c` payloads, at every byte offset and (for raw
DEFLATE) every bit offset within the first several KB:

- zlib / raw DEFLATE (wrapped and unwrapped)
- LZMA (both the "alone" format and standard framing)
- bzip2
- LZ4 (custom block decoder)
- classic LZSS / Okumura-style `lzhuf.c` (multiple initial ring-buffer states)
- MD5/SHA1/CRC32 (and ~15 CRC-32 parameter-set variants: BZIP2, MPEG-2, POSIX,
  Castagnoli, JAMCRC, AUTOSAR, Q/AIXM, XFER, ...) as candidates for the trailer
  checksum itself, over every plausible byte range of the file

None matched. The first ~1,536 bytes of `fw_a`'s payload are measurably
lower-entropy than the rest and contain a dense table of small 16/32-bit values
with many exact duplicate pairs — plausibly some kind of decode table — but we
were not able to determine its semantics or use it to unpack anything.

## PC-side dead ends

- The official updater tool named in the service manual (`KM532xxx.exe`) could
  not be located anywhere live. Kodak appears to have discontinued hosting this
  content around 2012.
- Third-party "driver download" aggregator sites still list the old file
  metadata, but the links are dead. At least one of them pushes a generic,
  unrelated "driver updater" PUP instead of the real file — worth knowing if you
  go looking.
- Inspected two different EasyShare "connection software" installers
  (InstallShield- and Inno Setup-based) and the camera's bundled autorun
  `image.iso`: none contain firmware, and none contain the checksum/packing
  logic — they're just the PC-side "install drivers, offer to install more
  software" bootstrap.

## USB enumeration

Live USB enumeration of the camera (Windows `Get-PnpDevice`) shows only a
standard `WPD`-class, PTP/MTP ("Still Image") device — the same generic
protocol virtually every digital camera has used since the mid-2000s, serviced
by Windows' own built-in `WUDFWpdMtp` driver. No vendor-specific secondary
interface, no sign of a factory/service mode, is exposed over a normal USB
connection. (The bootloader's symbol table does contain a full USB device
stack, so a different mode may exist — but if so, it isn't triggered by a
plain connection, and no documented button combination to force it was found.)

## Prior art

We could not find any public tooling or write-up for Zoran "COACH"-based camera
firmware — nothing resembling the CHDK/Magic Lantern ecosystem that exists for
Canon's DIGIC chips. The clearest confirmation of this gap we found was a
discussion of the same difficulty on a differently-branded camera using a
chip from the same family, noting that no extraction tools exist for Zoran-based
devices. If that has changed since, please let us know.

## Repo contents

- `tools/mips_dis.py` — a minimal, from-scratch MIPS32 (o32, little-endian)
  disassembler covering the common integer opcodes, written because no
  disassembler was available in the analysis environment. Good enough to hand-trace
  bootloader control flow; not a complete MIPS implementation.
- `tools/iso9660.py` — a small pure-Python ISO9660 reader (no Joliet/Rock Ridge),
  written to list/extract the bundled autorun `image.iso` without any system
  tooling available.
- `tools/cabparse.py` — a minimal Microsoft Cabinet (`.cab`) parser with MSZIP
  (raw DEFLATE + preset dictionary) support, for pulling installer payloads out
  of an InstallShield "Package for the Web" self-extractor.
- `tools/crcsweep.c` — a small C program sweeping ~15 parameterized CRC-32
  variants (polynomial/init/xorout/reflection) across candidate byte ranges, used
  to rule out the trailer checksum being a known CRC-32 flavor.

**Not included:** any Kodak-authored binary — no `.PAK` firmware file, no
installer, no camera ROM dump. If you want to reproduce this analysis, pull your
own firmware file from your own camera (see below).

## Reproducing this

1. Your M532 (or a sibling model on the same platform) will tell you its current
   firmware version under **Settings → About**.
2. The official procedure for extracting the current `.PAK` is documented in
   Kodak's own service manual for this model (search for "SM9595", "Kodak EasyShare
   M532 service manual") — it describes copying the firmware file to a
   `/system/` folder on an SD card for upgrades, which is also how we delivered
   our test files back to the device.
3. Once you have a `.PAK`, the file-offset map above should get you straight to
   the interesting parts without redoing the discovery work.

## How you can help

- **Know Zoran/CSR COACH internals?** The missing piece is the algorithm behind
  the hash/accumulator at `fw_a`+`0xFDF20` (file-relative; see
  [above](#locating-the-integrity-check)) and whatever unpacks `fw_a/b/c` into
  memory before it runs.
- **Have a working `KM532xxx.exe` or any Kodak M532 firmware ZIP/EXE from
  before ~2012?** The PC-side packer almost certainly contains the same
  algorithm in much more approachable x86 code.
- **Comfortable with a soldering iron?** The bootloader's symbol table strongly
  suggests a UART debug console exists on the board; we deliberately stopped
  short of opening the camera. A live memory dump post-decompression would
  make this whole compression question moot.

Issues and PRs welcome.

## License

This repository's own content (analysis, tooling, this document) is released
under the MIT License — see `LICENSE`. This project is not affiliated with or
endorsed by Eastman Kodak Company. All referenced Kodak trademarks and any
firmware/software described here remain the property of their respective owner.
