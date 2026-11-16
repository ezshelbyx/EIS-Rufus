//! EIS-Rufus - Bootable USB creation tool (Linux).
//!
//! DD-mode and ISO-mode image writing with safety checks, progress and
//! read-back verification, built on EIS-Storage-Core.

use eis_storage_core::device::{discover_block_devices, filter_removable_usb, BlockDevice};
use eis_storage_core::io::{CancellationToken, SafeReader, SafeWriter};
use eis_storage_core::safety::{SafetyGuard, SafetyPolicy};
use eis_storage_core::verify;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::process::exit;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("EIS-Rufus v{VERSION} - Bootable USB creation");
    println!();
    println!("Usage:");
    println!("  eis-rufus list                      List removable USB block devices");
    println!("  eis-rufus info <image>              Show image size and SHA-256");
    println!("  eis-rufus write <image> <target> [--force] [--no-verify]");
    println!("  eis-rufus verify <image> <target>");
    println!("  eis-rufus hash <file>");
    println!("  eis-rufus help");
}

fn cmd_list() {
    match discover_block_devices() {
        Ok(devs) => {
            let usb = filter_removable_usb(&devs);
            if usb.is_empty() {
                println!("No removable USB devices found.");
                return;
            }
            println!("{:<12} {:>12} {:<8} {}", "DEVICE", "SIZE", "RM", "MODEL");
            for d in usb {
                println!(
                    "{:<12} {:>12} {:<8} {}",
                    d.path,
                    d.size_bytes,
                    if d.removable { "yes" } else { "no" },
                    d.model.as_deref().unwrap_or("-")
                );
            }
        }
        Err(e) => {
            eprintln!("device discovery failed: {e}");
            exit(1);
        }
    }
}

fn cmd_info(image: &str) {
    let meta = match fs::metadata(image) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("cannot stat {image}: {e}");
            exit(1);
        }
    };
    println!("Image: {image}");
    println!(
        "Size:  {} bytes ({} MiB)",
        meta.len(),
        meta.len() / (1024 * 1024)
    );
    match SafeReader::open(image) {
        Ok(mut r) => match r.hash(eis_storage_core::crypto::HashAlgorithm::Sha256) {
            Ok(h) => println!("SHA-256: {h}"),
            Err(e) => eprintln!("hash failed: {e}"),
        },
        Err(e) => eprintln!("open failed: {e}"),
    }
}

fn write_image(image: &str, target: &str, force: bool, verify_after: bool) {
    let img_size = match fs::metadata(image) {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("cannot stat image {image}: {e}");
            exit(1);
        }
    };

    // Safety guard for block device targets
    let guard = SafetyGuard::default_guard();
    if target.starts_with("/dev/") {
        match discover_block_devices() {
            Ok(devs) => {
                if let Some(dev) = devs.iter().find(|d| d.path == target) {
                    if !force {
                        if !dev.removable {
                            eprintln!("Refusing to write to non-removable device {target}. Use --force to override.");
                            exit(1);
                        }
                        if !guard.check_write_target(dev).is_ok() {
                            eprintln!("Safety check failed for {target}.");
                            exit(1);
                        }
                    }
                } else {
                    eprintln!("Target {target} not found in device list.");
                    exit(1);
                }
            }
            Err(e) => eprintln!("device discovery failed: {e}"),
        }
    }

    // Optional confirmation for destructive block writes
    if target.starts_with("/dev/") && !force {
        eprint!("This will overwrite {target}. Type 'YES' to continue: ");
        let _ = std::io::stderr().flush();
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        if input.trim() != "YES" {
            eprintln!("Aborted.");
            exit(1);
        }
    }

    println!("Writing {} ({} bytes) -> {}", image, img_size, target);

    // Open source
    let mut src = match SafeReader::open(image) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("open image failed: {e}");
            exit(1);
        }
    };

    // Open target writer
    let cancel = CancellationToken::new();
    let writer = if target.starts_with("/dev/") {
        SafeWriter::open_device(target)
    } else {
        SafeWriter::create(target)
    };
    let mut writer = match writer {
        Ok(w) => w,
        Err(e) => {
            eprintln!("open target failed: {e}");
            exit(1);
        }
    };

    let mut progress = |written: u64, total: u64| {
        let pct = if total > 0 {
            (written as f64 / total as f64 * 100.0) as u32
        } else {
            0
        };
        print!("\r  {} / {} bytes ({}%)", written, total, pct);
        let _ = std::io::stdout().flush();
    };

    if let Err(e) = writer.write_stream(&mut *src.file_mut(), img_size, &mut progress, Some(cancel))
    {
        eprintln!("\nwrite failed: {e}");
        exit(1);
    }
    println!();

    // fsync
    if let Err(e) = writer.sync() {
        eprintln!("sync failed: {e}");
    }

    if verify_after {
        println!("Verifying...");
        match verify::verify_image_hash(image, target) {
            Ok(r) => {
                if r.success {
                    println!("Verification OK (SHA-256 match).");
                } else {
                    eprintln!("Verification FAILED.");
                    eprintln!("  expected: {}", r.expected_hash.unwrap_or_default());
                    eprintln!("  actual:   {}", r.actual_hash.unwrap_or_default());
                    exit(1);
                }
            }
            Err(e) => {
                eprintln!("verify failed: {e}");
                exit(1);
            }
        }
    } else {
        println!("Write complete (verification skipped).");
    }
}

fn cmd_verify(image: &str, target: &str) {
    match verify::verify_image_hash(image, target) {
        Ok(r) => {
            if r.success {
                println!("OK: {} matches {}", target, image);
            } else {
                eprintln!("MISMATCH");
                eprintln!("  expected: {}", r.expected_hash.unwrap_or_default());
                eprintln!("  actual:   {}", r.actual_hash.unwrap_or_default());
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("verify failed: {e}");
            exit(1);
        }
    }
}

fn cmd_hash(file: &str) {
    match SafeReader::open(file) {
        Ok(mut r) => match r.hash(eis_storage_core::crypto::HashAlgorithm::Sha256) {
            Ok(h) => println!("{h}  {file}"),
            Err(e) => {
                eprintln!("hash failed: {e}");
                exit(1);
            }
        },
        Err(e) => {
            eprintln!("open failed: {e}");
            exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }
    match args[1].as_str() {
        "list" => cmd_list(),
        "info" => {
            if args.len() < 3 {
                eprintln!("missing image path");
                exit(1);
            }
            cmd_info(&args[2]);
        }
        "write" => {
            if args.len() < 4 {
                eprintln!("usage: write <image> <target> [--force] [--no-verify]");
                exit(1);
            }
            let image = args[2].clone();
            let target = args[3].clone();
            let mut force = false;
            let mut no_verify = false;
            for a in &args[4..] {
                match a.as_str() {
                    "--force" => force = true,
                    "--no-verify" => no_verify = true,
                    _ => {}
                }
            }
            write_image(&image, &target, force, !no_verify);
        }
        "verify" => {
            if args.len() < 4 {
                eprintln!("usage: verify <image> <target>");
                exit(1);
            }
            cmd_verify(&args[2], &args[3]);
        }
        "hash" => {
            if args.len() < 3 {
                eprintln!("usage: hash <file>");
                exit(1);
            }
            cmd_hash(&args[2]);
        }
        "help" | "--help" | "-h" => print_help(),
        _ => {
            eprintln!("unknown command: {}", args[1]);
            print_help();
            exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn write_and_verify_roundtrip() {
        let dir = std::env::temp_dir();
        let img = dir.join("eis_rufus_test.img");
        let tgt = dir.join("eis_rufus_target.img");
        let data: Vec<u8> = (0..4096u32).map(|i| (i & 0xff) as u8).collect();
        fs::write(&img, &data).unwrap();
        // simulate write via SafeWriter
        let mut w = SafeWriter::create(tgt.to_str().unwrap()).unwrap();
        let mut f = fs::File::open(&img).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        w.write_all(&buf).unwrap();
        w.sync().unwrap();
        assert!(
            verify::verify_image_hash(img.to_str().unwrap(), tgt.to_str().unwrap())
                .unwrap()
                .success
        );
        let _ = fs::remove_file(&img);
        let _ = fs::remove_file(&tgt);
    }

    #[test]
    fn info_does_not_panic() {
        let dir = std::env::temp_dir();
        let p = dir.join("eis_rufus_info.bin");
        fs::write(&p, b"hello").unwrap();
        cmd_hash(p.to_str().unwrap());
        let _ = fs::remove_file(&p);
    }
}
