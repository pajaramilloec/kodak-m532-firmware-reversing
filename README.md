# Reverse Engineering the Kodak EasyShare M532 Firmware Update Format

> Status: open / unsolved. This is a research log, not a working hack. The camera's firmware image is still opaque at the time of writing. Published in the hope that someone with more experience in embedded Zoran/CSR "COACH" platforms, proprietary LZ/Huffman schemes, or JTAG/UART bring-up can pick up where this leaves off.

## TL;DR

The Kodak EasyShare M532 (2011, Service Code 9595) is built on a Zoran/CSR "COACH" SoC running MIPS32r2, little-endian. Its firmware update package (`M532_110.PAK`, ~20.7 MB) contains two small, fully-readable MIPS ELF binaries (a secondary bootloader and a flash-programming tool) and three large ELF images that make up the actual camera application — and those three are either custom LZ/entropy-compressed or encrypted with an undocumented, proprietary scheme.

We fully mapped the file format, located the exact function that validates the package's integrity, and confirmed — empirically, on real hardware, five separate times — that the checksum covers the entire file with no gaps. **We were not able to identify the compression/hash algorithm itself**, because the code that implements it lives inside the one part of the image we can't read.

No public documentation, tooling, or prior write-up for this SoC family appears to exist (see **Prior Art**). If you know this platform, please open an issue — see **How You Can Help**.

## Table of Contents
* Why
* Disclaimer
* Platform identification
* The .PAK file format
* Locating the integrity check
* On-device differential testing
* Compression schemes ruled out
* PC-side dead ends
* USB enumeration
* Prior art
* Repo contents
* Reproducing this
* How you can help
* License

## Why
The M532 is a disposable-grade point-and-shoot: cheap, long discontinued, and Kodak pulled its firmware/software downloads from its own servers around 2012. That combination — worthless resale value, dead official support, completely undocumented SoC — makes it a reasonable target for a no-stakes reverse engineering exercise. Worst case, it stays a $5 paperweight it already was.

## Disclaimer
This is personal research on a personally-owned, end-of-life device, done for educational purposes. Nothing here is intended to defeat any DRM, access control, or copy protection on copyrighted content — it concerns a camera's own firmware update mechanism. No Kodak binaries, installers, or copyrighted material are included in this repository (see **Repo contents**).

## Platform identification
Strings and symbol names recovered from the firmware package identify:
* **SoC family**: Zoran "COACH" (the string `AppGetCoachVersion` appears in the bootloader; Zoran's imaging SoCs were widely used in low-end 2008–2012 cameras under several brands)
* **CPU**: MIPS32r2, little-endian, o32 ABI (`noreorder`, confirmed via raw ELF headers: `EM_MIPS`, `e_flags = 0x70001001`)
* **CCD sensor (not CMOS)** per the official service manual
* **USB**: standard PTP/MTP ("Still Image" class, `USB\Class_06&SubClass_01`), `VID_040A` (Eastman Kodak Company's registered USB-IF vendor ID) `PID_0611`

## The .PAK file format
The firmware package (e.g. `M532_110.PAK`, firmware version `01.100000`) is a flat binary, no wrapper container, laid out as:

```text
0x000000 - 0x0001FF   512-byte header. Dense table of (address, value)-looking 
                      pairs in the 0x20xx range — almost certainly an early 
                      hardware bring-up table (clocks / memory controller), still 
                      not padding. (Confirmed: modifying any byte here 
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
                        - a debug-instrumented pool allocator (PoolGetEx, PoolFreeEx, 
                          PoolDump, leak-detection helpers)

0x102640              ELF #2, "burn_tool": the firmware-flashing tool. 
                      Also fully readable MIPS32 code, but with its symbol table 
                      stripped. Contains the literal ASCII tags used by the 
                      trailer format below, and the function that validates them 
                      (see next section).

0x220240              ELF #3, "fw_a": first segment of the actual camera OS/app.
0x3A8138              ELF #4, "fw_b": second segment.
0x5DCDD4              ELF #5, "fw_c": third segment.
                      Combined, ~20 MB. Byte entropy is uniformly ~7.5-7.84 readable 
                      bits/byte throughout (vs. 2-6.7 for the plainly-boot0/burn_tool 
                      code) — consistent with compression or encryption. This is the 
                      part we could not break.

...$SCRIPT$ \r\n       Trailer, literal ASCII, appended with no padding before
$CHECKSUM$<4 bytes>   or after it. <4 bytes> is a raw, non-ASCII 32-bit value —
$VERSION$ \r\n        the integrity value the camera checks on upgrade.
0x01100000\r\n
