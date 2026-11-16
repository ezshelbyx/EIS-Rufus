# EIS Rufus

USB imaging and bootable media creation tool.

## Overview

EIS Rufus is a desktop application for creating bootable USB drives from ISO images. Inspired by Rufus, built with native Linux technologies and Rust.

## Stack

- Rust core for imaging operations
- Native Linux GUI (GTK4 or egui)
- Safety-first: verifies target device is USB before writing

## Safety

- Verifies target is a removable USB device before any write
- Requires explicit user confirmation for destructive operations
- Never targets internal storage

## Build

```bash
cargo build
cargo run
```

## Roadmap

- [ ] M01: Project scaffold
- [ ] M02: ISO/IMG selection and validation
- [ ] M03: USB device detection and verification
- [ ] M04: Bootable media creation (FAT32/NTFS/exFAT)
- [ ] M05: Progress reporting
- [ ] M06: Verification (SHA-256)
- [ ] M07: Bad block checking
