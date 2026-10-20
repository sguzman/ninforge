//! Standalone Ninforge binary. No external runtime service dependencies.

use ninforge::cnmt::inspect_cnmt;
use ninforge::metadata_dir::discover_metadata_dir;
use ninforge::nacp::inspect_nacp;
use ninforge::nca::inspect_decrypted_nca;
use ninforge::nds_save::{inspect_ds_save, DsSaveReport};
use ninforge::package::{
    audit_switch_package, audit_switch_package_with_hashes, audit_switch_package_with_headers,
    HashStatus, HeaderStatus, MatchStatus, PackageAudit,
};
use ninforge::title_inventory::{inventory_metadata_root_with_packages, TitleInventory};
use ninforge::wii::{
    inspect_wii_disc, inspect_wii_partition_headers, validate_wbfs_maps, WbfsMapReport,
    WiiDiscReport, WiiPartitionHeader,
};
use ninforge::{extract_entry, inspect, saves, Entry, Format, Report};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("ninforge: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [cmd] if cmd == "--help" || cmd == "-h" || cmd == "help" => usage(),
        [cmd] if cmd == "--version" || cmd == "-V" => {
            println!("ninforge {}", env!("CARGO_PKG_VERSION"))
        }
        [cmd, file] if cmd == "info" || cmd == "inspect" => {
            let report = inspect(&mut File::open(file)?)?;
            print_report(&report, false);
        }
        [cmd, file, flag] if (cmd == "info" || cmd == "inspect") && flag == "--json" => {
            let report = inspect(&mut File::open(file)?)?;
            println!("{}", report_json(&report, false));
        }
        [cmd, file] if cmd == "list" => {
            let report = inspect(&mut File::open(file)?)?;
            require_sections(&report)?;
            for entry in &report.entries {
                println!("{}\t{}", entry.size, entry.name);
            }
        }
        [cmd, file, flag] if cmd == "list" && flag == "--json" => {
            let report = inspect(&mut File::open(file)?)?;
            require_sections(&report)?;
            println!("{}", report_json(&report, true));
        }
        [cmd, file] if cmd == "verify" => {
            let report = inspect(&mut File::open(file)?)?;
            match report.format {
                Format::GameBoy | Format::GameBoyColor => {
                    let bytes = ninforge::gb::verify_game_boy(&mut File::open(file)?)?;
                    println!(
                        "OK: {} header, declared ROM size and global checksum match ({} bytes; additive CRC-free sum, not a signature)",
                        report.format, bytes
                    );
                }
                Format::GameBoyAdvance => {
                    ninforge::gba::verify_gba_header(&mut File::open(file)?)?;
                    println!("OK: GBA fixed header, complement checksum and weak logo sum match (header-only; no full-ROM checksum, signature or logo byte authentication)");
                }
                Format::NintendoDs => {
                    require_sections(&report)?;
                    verify_ds_checks(&report)?;
                    println!(
                        "OK: {} region bounds and cartridge CRC-16 checks are valid (not a cryptographic signature)",
                        report.entries.len()
                    );
                }
                Format::Wii => {
                    println!("OK: Wii disc partition-table offsets are structurally bounded (encrypted partition data not verified)");
                }
                Format::WiiWbfs => {
                    println!("OK: WBFS superblock and disc-slot table are structurally readable (disc block maps and game data not verified)");
                }
                _ => {
                    require_sections(&report)?;
                    println!(
                        "OK: {} header and {} region bounds are structurally valid (not a hash/signature check)",
                        report.format, report.entries.len()
                    );
                }
            }
        }
        [platform, action, file] if platform == "wii" && action == "partition-check" => {
            run_wii_partition_check(file, false)?;
        }
        [platform, action, file, flag]
            if platform == "wii" && action == "partition-check" && flag == "--json" =>
        {
            run_wii_partition_check(file, true)?;
        }
        [platform, action, file] if platform == "wii" && action == "wbfs-check" => {
            run_wbfs_check(file, false)?;
        }
        [platform, action, file, flag]
            if platform == "wii" && action == "wbfs-check" && flag == "--json" =>
        {
            run_wbfs_check(file, true)?;
        }
        [platform, action, file] if platform == "wii" && action == "partitions" => {
            run_wii_partitions(file, false)?;
        }
        [platform, action, file, flag]
            if platform == "wii" && action == "partitions" && flag == "--json" =>
        {
            run_wii_partitions(file, true)?;
        }
        [platform, save, action, file]
            if platform == "nds" && save == "save" && action == "info" =>
        {
            print_nds_save(&inspect_ds_save(&mut File::open(file)?)?, false);
        }
        [platform, save, action, file, flag]
            if platform == "nds" && save == "save" && action == "info" && flag == "--json" =>
        {
            print_nds_save(&inspect_ds_save(&mut File::open(file)?)?, true);
        }
        [cmd, sub, root] if cmd == "saves" && sub == "scan" => save_scan(Path::new(root), false)?,
        [cmd, sub, root, flag] if cmd == "saves" && sub == "scan" && flag == "--json" => {
            save_scan(Path::new(root), true)?
        }
        [cmd, sub, source, destination] if cmd == "saves" && sub == "backup" => {
            let copied = saves::backup(Path::new(source), Path::new(destination))?;
            println!("Backed up {copied} bytes to {destination} (source untouched)");
        }
        [cmd, sub, rest @ ..] if cmd == "titles" && sub == "inventory" => {
            run_titles_inventory(rest)?;
        }
        [cmd, sub, rest @ ..] if cmd == "package" && sub == "audit" => {
            run_package_audit(rest)?;
        }
        [cmd, sub, rest @ ..] if cmd == "package" && sub == "audit-dir" => {
            run_package_audit_dir(rest)?;
        }
        [cmd, sub, file] if cmd == "nca" && sub == "info" => {
            let report = inspect_decrypted_nca(&mut File::open(file)?)?;
            print_report(&report, false);
        }
        [cmd, sub, file, flag] if cmd == "nca" && sub == "info" && flag == "--json" => {
            let report = inspect_decrypted_nca(&mut File::open(file)?)?;
            println!("{}", report_json(&report, false));
        }
        [cmd, sub, file] if cmd == "cnmt" && sub == "info" => {
            let report = inspect_cnmt(&mut File::open(file)?)?;
            print_report(&report, false);
        }
        [cmd, sub, file, flag] if cmd == "cnmt" && sub == "info" && flag == "--json" => {
            let report = inspect_cnmt(&mut File::open(file)?)?;
            println!("{}", report_json(&report, false));
        }
        [cmd, sub, file] if cmd == "nacp" && sub == "info" => {
            let report = inspect_nacp(&mut File::open(file)?)?;
            print_report(&report, false);
        }
        [cmd, sub, file, flag] if cmd == "nacp" && sub == "info" && flag == "--json" => {
            let report = inspect_nacp(&mut File::open(file)?)?;
            println!("{}", report_json(&report, false));
        }
        [cmd, directory] if cmd == "scan" => scan(Path::new(directory), false)?,
        [cmd, directory, flag] if cmd == "scan" && flag == "--json" => {
            scan(Path::new(directory), true)?
        }
        [cmd, input, entry_name, output] if cmd == "extract" => {
            let mut archive = File::open(input)?;
            let report = inspect(&mut archive)?;
            require_sections(&report)?;
            let matches: Vec<&Entry> = report
                .entries
                .iter()
                .filter(|entry| entry.name == *entry_name)
                .collect();
            let [entry] = matches.as_slice() else {
                return Err(format!(
                    "expected exactly one entry named {entry_name:?}, found {}",
                    matches.len()
                )
                .into());
            };
            // Explicit output is never derived from a potentially malicious archive filename.
            // create_new rejects existing paths and symlinks rather than overwriting a save.
            let destination = Path::new(output);
            let mut sink = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?;
            let result =
                extract_entry(&mut archive, entry, &mut sink).and_then(|_| sink.sync_all());
            if let Err(error) = result {
                drop(sink);
                let _ = fs::remove_file(destination);
                return Err(error.into());
            }
            println!(
                "Extracted {} bytes to {}",
                entry.size,
                destination.display()
            );
        }
        [] => usage(),
        _ => return Err("invalid arguments; run 'ninforge help'".into()),
    }
    Ok(())
}

/// Read-only integrity check of already computed NDS header/banner CRCs.
/// Missing header fields never count as valid; an absent banner is permitted.
fn verify_ds_checks(report: &Report) -> Result<(), Box<dyn std::error::Error>> {
    if report.format != Format::NintendoDs {
        return Err("DS integrity checks require a recognized Nintendo DS cartridge".into());
    }
    for (field, label) in [
        ("nds_logo_crc_valid", "logo CRC-16"),
        ("nds_header_crc_valid", "header CRC-16"),
    ] {
        if !report
            .metadata
            .iter()
            .any(|(key, value)| key == field && value == "true")
        {
            return Err(format!("Nintendo DS {label} mismatch or unavailable").into());
        }
    }
    if report
        .metadata
        .iter()
        .any(|(key, value)| key == "banner_crc_all_valid" && value == "false")
    {
        return Err("Nintendo DS banner CRC-16 mismatch".into());
    }
    Ok(())
}

fn require_sections(report: &Report) -> Result<(), Box<dyn std::error::Error>> {
    match report.format {
        Format::SwitchNsp | Format::SwitchHfs0 | Format::SwitchXci | Format::NintendoDs => Ok(()),
        _ => Err("this operation supports Switch NSP/HFS0/XCI and Nintendo DS files".into()),
    }
}

/// Inspect recognized files under a directory without following symlinks.
/// Results are streamed in lexical order, not buffered in memory.
fn scan(root: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !root.is_dir() {
        return Err(format!("not a directory: {}", root.display()).into());
    }
    let mut stack = vec![root.to_path_buf()];
    let mut errors = 0u64;
    while let Some(path) = stack.pop() {
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            let mut children: Vec<PathBuf> = fs::read_dir(&path)?
                .map(|item| item.map(|entry| entry.path()))
                .collect::<Result<_, _>>()?;
            children.sort();
            stack.extend(children.into_iter().rev());
            continue;
        }
        if !kind.is_file() {
            continue;
        }
        match File::open(&path).and_then(|mut input| inspect(&mut input)) {
            Ok(report) if report.format != Format::Unknown => {
                if json {
                    println!(
                        "{{\"path\":{},\"report\":{}}}",
                        json_string(&path.to_string_lossy()),
                        report_json(&report, false)
                    );
                } else {
                    println!(
                        "{}\t{}\t{}\t{}",
                        report.format.console(),
                        report.format,
                        report.bytes,
                        path.display()
                    );
                }
            }
            Ok(_) => {}
            Err(error) => {
                errors += 1;
                eprintln!("ninforge: {}: {error}", path.display());
            }
        }
    }
    if errors != 0 {
        return Err(format!("scan encountered {errors} unreadable or malformed file(s)").into());
    }
    Ok(())
}

fn save_scan(root: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    for save in saves::inventory(root)? {
        if json {
            println!(
                "{{\"path\":{},\"size_bytes\":{},\"hint\":{},\"verified\":false}}",
                json_string(&save.path.to_string_lossy()),
                save.size,
                json_string(save.hint)
            );
        } else {
            println!("{}\t{}\t{}", save.size, save.hint, save.path.display());
        }
    }
    Ok(())
}

fn usage() {
    println!(
        "\
Ninforge {} - Nintendo file inspection (read-only by default)

Usage:
  ninforge info <file> [--json]            Detect format and inspect header
  ninforge inspect <file> [--json]         Alias for info
  ninforge list <file> [--json]            List NSP/HFS0/XCI entries or DS files
  ninforge verify <file>                   Validate supported structural/checksum checks
  ninforge wii partitions <iso> [--json]  Index Wii ISO partition table (not decrypt)
  ninforge wii partition-check <iso> [--json]  Check Wii partition metadata extents
  ninforge wii wbfs-check <file> [--json]  Validate WBFS disc records and block maps
  ninforge extract <file> <entry> <out>    Extract one entry/section; no overwrite
  ninforge scan <directory> [--json]       Recursive recognized-file inventory
  ninforge nacp info <file> [--json]       Read decrypted control.nacp metadata
  ninforge nca info <file> [--json]        Inspect already-decrypted NCA header
  ninforge package audit <nsp-or-xci> <cnmt> [--nacp <file>] [--main-nso <file>] [--headers] [--hash] [--json]
                                           Inspect NSP + explicit external metadata
  ninforge package audit-dir <nsp-or-xci> <metadata-dir> [--headers] [--hash] [--json]
                                           Discover unique plaintext metadata sidecars
  ninforge cnmt info <file> [--json]       Parse standalone plaintext CNMT
  ninforge titles inventory <root> [--packages] [--hash] [--headers] [--json]
                                           Index immediate metadata bundle folders
  ninforge nds save info <file> [--json] Inspect DS save wrappers, do not infer title
  ninforge saves scan <dir> [--json]       Discover save candidates by extension
  ninforge saves backup <src> <out>        Atomic no-overwrite copy of one save
  ninforge help                            Show this help

Limitations:
  No decryption, save editing, signing, repacking, or full cryptographic verify.
  Scanning skips symlinks; --json scan output is newline-delimited JSON.
  NSP/PFS0 listing does not require Nintendo keys; many encrypted inner files do.
",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_report(report: &Report, list: bool) {
    println!("Format: {}", report.format);
    println!("Console: {}", report.format.console());
    println!("Bytes: {}", report.bytes);
    for (key, value) in &report.metadata {
        println!("{key}: {value}");
    }
    if list {
        for entry in &report.entries {
            println!("{}\t{}", entry.size, entry.name);
        }
    }
}

/// DS-save inspection is intentionally explicit, because a raw file has no
/// unique Nintendo DS signature and must not be auto-attributed to a game.
fn print_nds_save(report: &DsSaveReport, json: bool) {
    if !json {
        println!("DS save candidate format: {}", report.kind.label());
        println!("Size: {} bytes", report.size_bytes);
        for (name, value) in &report.metadata {
            println!("{name}: {value}");
        }
        return;
    }
    let mut output = format!(
        r#"{{"format":{},"size_bytes":{},"metadata":{{"#,
        json_string(report.kind.label()),
        report.size_bytes
    );
    for (index, (name, value)) in report.metadata.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write!(&mut output, "{}:{}", json_string(name), json_string(value))
            .expect("formatting JSON string");
    }
    output.push_str("}}");
    println!("{output}");
}

/// Wii ISO partition positions are addresses; their sizes and encrypted
/// contents have not been validated and are never exposed to extraction.
/// Strict opt-in validation of the plaintext ticket-adjacent offsets only.
/// Does not read or authenticate TMD/certificate bytes, H3 hashes, or game data.
fn run_wii_partition_check(path: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let report = inspect(&mut file)?;
    if report.format != Format::Wii {
        return Err("wii partition-check requires a raw Wii ISO, not WBFS".into());
    }
    let partitions = inspect_wii_partition_headers(&mut file, report.bytes)?;
    print_wii_partition_checks(&partitions, json);
    Ok(())
}

fn print_wii_partition_checks(partitions: &[WiiPartitionHeader], json: bool) {
    if !json {
        println!("Checked {} Wii partition header layouts", partitions.len());
        for part in partitions {
            println!(
                "group={} index={} base={} type={} tmd={}:{} cert={:?}:{} h3={:?} data={}:{}",
                part.group,
                part.index,
                part.partition_offset_bytes,
                part.partition_type,
                part.tmd_offset_bytes,
                part.tmd_size_bytes,
                part.cert_offset_bytes,
                part.cert_size_bytes,
                part.h3_offset_bytes,
                part.data_offset_bytes,
                part.data_size_bytes
            );
        }
        println!(
            "Only byte-range bounds were checked; signatures and encrypted data are unverified."
        );
        return;
    }
    let mut out = format!(
        r#"{{"format":"wii_partition_header_check","partition_count":{},"signature_verified":false,"encrypted_content_verified":false,"partitions":["#,
        partitions.len()
    );
    for (index, part) in partitions.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let cert = part
            .cert_offset_bytes
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        let h3 = part
            .h3_offset_bytes
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        write!(&mut out,
            r#"{{"group":{},"index":{},"partition_offset_bytes":{},"type":{},"tmd_offset_bytes":{},"tmd_size_bytes":{},"cert_offset_bytes":{},"cert_size_bytes":{},"h3_offset_bytes":{},"data_offset_bytes":{},"data_size_bytes":{}}}"#,
            part.group, part.index, part.partition_offset_bytes,
            part.partition_type, part.tmd_offset_bytes, part.tmd_size_bytes,
            cert, part.cert_size_bytes, h3,
            part.data_offset_bytes, part.data_size_bytes
        ).expect("JSON formatting");
    }
    out.push_str("]}");
    println!("{out}");
}

fn run_wii_partitions(path: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let report = inspect(&mut file)?;
    if report.format != Format::Wii {
        return Err("wii partitions requires a raw Wii ISO, not a WBFS container".into());
    }
    let disc = inspect_wii_disc(&mut file, report.bytes)?;
    print_wii_partitions(&disc, json);
    Ok(())
}

/// Explicit, bounded WBFS metadata read: ordinary "info" remains superblock
/// only. This refuses invalid/truncated wlba indices without touching game data.
fn run_wbfs_check(path: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let report = inspect(&mut file)?;
    if report.format != Format::WiiWbfs {
        return Err("wii wbfs-check requires a WBFS container".into());
    }
    let checked = validate_wbfs_maps(&mut file, report.bytes)?;
    print_wbfs_check(&checked, json);
    Ok(())
}

fn print_wbfs_check(report: &WbfsMapReport, json: bool) {
    if !json {
        println!(
            "WBFS: {} occupied records, {} mapped blocks (record {} bytes)",
            report.checked_slots, report.mapped_blocks_total, report.disc_record_size_bytes,
        );
        for disc in &report.discs {
            println!(
                "slot={} id={} mapped_blocks={} logical_blocks={} info_offset={}",
                disc.slot,
                disc.disc_id,
                disc.mapped_blocks,
                disc.logical_blocks,
                disc.info_offset_bytes
            );
        }
        println!("Block references are within file bounds; game data and cryptographic hashes are NOT verified.");
        return;
    }
    let mut output = format!(
        r#"{{"format":"wbfs_map_check","occupied_slots":{},"mapped_blocks":{},"host_sector_bytes":{},"wbfs_sector_bytes":{},"declared_capacity_bytes":{},"disc_record_size_bytes":{},"physical_block_count":{},"logical_blocks_per_disc":{},"block_references_within_file":{},"encrypted_content_verified":false,"discs":["#,
        report.checked_slots,
        report.mapped_blocks_total,
        report.host_sector_bytes,
        report.wbfs_sector_bytes,
        report.declared_capacity_bytes,
        report.disc_record_size_bytes,
        report.physical_block_count,
        report.logical_blocks_per_disc,
        report.block_references_within_file,
    );
    for (index, disc) in report.discs.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        let last = disc
            .last_physical_block
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        write!(
            &mut output,
            r#"{{"slot":{},"disc_id":{},"info_offset_bytes":{},"mapped_blocks":{},"logical_blocks":{},"last_physical_block":{}}}"#,
            disc.slot, json_string(&disc.disc_id), disc.info_offset_bytes,
            disc.mapped_blocks, disc.logical_blocks, last
        ).expect("JSON formatting");
    }
    output.push_str("]}");
    println!("{output}");
}

fn print_wii_partitions(disc: &WiiDiscReport, json: bool) {
    if !json {
        println!("Wii partition groups: {:?}", disc.group_counts);
        println!("Partition entries: {}", disc.partitions.len());
        for part in &disc.partitions {
            println!(
                "group={} index={} offset={} type={} ({})",
                part.group,
                part.index,
                part.offset_bytes,
                part.partition_type,
                part.kind()
            );
        }
        println!("Encrypted partitions and their lengths are not verified.");
        return;
    }
    let mut output = format!(
        r#"{{"format":"wii_partition_table","partition_count":{},"groups":["#,
        disc.partitions.len()
    );
    for group in 0..4 {
        if group > 0 {
            output.push(',');
        }
        let pointer = disc.group_table_offsets[group]
            .map_or_else(|| "null".to_string(), |offset| offset.to_string());
        write!(
            &mut output,
            r#"{{"index":{},"count":{},"table_offset_bytes":{}}}"#,
            group, disc.group_counts[group], pointer
        )
        .expect("String write");
    }
    output.push_str(r#"],"region_code":"#);
    output.push_str(
        &disc
            .region_code
            .map_or_else(|| "null".to_owned(), |code| code.to_string()),
    );
    output.push_str(r#","partitions":["#);
    for (index, part) in disc.partitions.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write!(
            &mut output,
            r#"{{"group":{},"index":{},"offset_bytes":{},"type":{},"type_name":{}}}"#,
            part.group,
            part.index,
            part.offset_bytes,
            part.partition_type,
            json_string(part.kind())
        )
        .expect("String write");
    }
    output.push_str(r#"],"encrypted_content_verified":false}"#);
    println!("{output}");
}

fn report_json(report: &Report, include_entries: bool) -> String {
    let mut text = format!(
        "{{\"format\":{},\"console\":{},\"size_bytes\":{},\"metadata\":{{",
        json_string(report.format.name()),
        json_string(report.format.console()),
        report.bytes,
    );
    for (i, (key, value)) in report.metadata.iter().enumerate() {
        if i != 0 {
            text.push(',');
        }
        write!(&mut text, "{}:{}", json_string(key), json_string(value)).expect("String write");
    }
    text.push('}');
    if include_entries {
        text.push_str(",\"entries\":[");
        for (i, entry) in report.entries.iter().enumerate() {
            if i != 0 {
                text.push(',');
            }
            write!(
                &mut text,
                "{{\"name\":{},\"offset\":{},\"size_bytes\":{}}}",
                json_string(&entry.name),
                entry.offset,
                entry.size
            )
            .expect("String write");
        }
        text.push(']');
    }
    text.push('}');
    text
}

#[derive(Debug, Default, PartialEq, Eq)]
struct PackageFlags<'a> {
    json: bool,
    hash: bool,
    headers: bool,
    nacp: Option<&'a str>,
    main_nso: Option<&'a str>,
}

fn parse_package_flags(args: &[String]) -> Result<PackageFlags<'_>, Box<dyn std::error::Error>> {
    let mut flags = PackageFlags::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" if !flags.json => {
                flags.json = true;
                i += 1;
            }
            "--hash" if !flags.hash => {
                flags.hash = true;
                i += 1;
            }
            "--headers" if !flags.headers => {
                flags.headers = true;
                i += 1;
            }
            "--nacp" if flags.nacp.is_none() => {
                flags.nacp = Some(
                    args.get(i + 1)
                        .filter(|value| !value.starts_with("--"))
                        .ok_or("--nacp requires a filepath")?,
                );
                i += 2;
            }
            "--main-nso" if flags.main_nso.is_none() => {
                flags.main_nso = Some(
                    args.get(i + 1)
                        .filter(|value| !value.starts_with("--"))
                        .ok_or("--main-nso requires a filepath")?,
                );
                i += 2;
            }
            other => {
                return Err(
                    format!("unknown, repeated, or malformed package option: {other}").into(),
                )
            }
        }
    }
    Ok(flags)
}

fn run_package_audit(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [nsp, cnmt, flags @ ..] = args else {
        return Err(
            "usage: ninforge package audit <nsp-or-xci> <cnmt> [--nacp <file>] [--main-nso <file>] [--headers] [--hash] [--json]"
                .into(),
        );
    };
    let parsed = parse_package_flags(flags)?;
    let mut audit =
        load_package_audit(Path::new(nsp), Path::new(cnmt), parsed.hash, parsed.headers)?;
    if let Some(path) = parsed.nacp {
        audit.attach_nacp(&mut File::open(path)?)?;
    }
    if let Some(path) = parsed.main_nso {
        audit.attach_main_nso(&mut File::open(path)?)?;
    }
    if parsed.json {
        println!("{}", package_audit_json(&audit));
    } else {
        print_package_audit(&audit);
    }
    Ok(())
}

fn load_package_audit(
    nsp: &Path,
    cnmt: &Path,
    hash: bool,
    headers: bool,
) -> Result<PackageAudit, Box<dyn std::error::Error>> {
    let mut archive = File::open(nsp)?;
    let mut metadata = File::open(cnmt)?;
    if headers {
        Ok(audit_switch_package_with_headers(
            &mut archive,
            &mut metadata,
            hash,
        )?)
    } else if hash {
        Ok(audit_switch_package_with_hashes(
            &mut archive,
            &mut metadata,
        )?)
    } else {
        Ok(audit_switch_package(&mut archive, &mut metadata)?)
    }
}

/// A deliberately conservative shortcut: read only files directly within the
/// chosen metadata directory. Ambiguous CNMT/NACP candidates fail closed.
fn run_package_audit_dir(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [nsp, metadata_dir, flags @ ..] = args else {
        return Err(
            "usage: ninforge package audit-dir <nsp-or-xci> <metadata-dir> [--headers] [--hash] [--json]"
                .into(),
        );
    };
    let parsed = parse_package_flags(flags)?;
    if parsed.nacp.is_some() || parsed.main_nso.is_some() {
        return Err(
            "audit-dir discovers metadata; use 'package audit' for explicit --nacp/--main-nso"
                .into(),
        );
    }
    let sidecars = discover_metadata_dir(Path::new(metadata_dir))?;
    let mut audit =
        load_package_audit(Path::new(nsp), &sidecars.cnmt, parsed.hash, parsed.headers)?;
    if let Some(path) = sidecars.nacp {
        audit.attach_nacp(&mut File::open(path)?)?;
    }
    if let Some(path) = sidecars.main_nso {
        audit.attach_main_nso(&mut File::open(path)?)?;
    }
    if parsed.json {
        println!("{}", package_audit_json(&audit));
    } else {
        print_package_audit(&audit);
    }
    Ok(())
}

fn print_package_audit(audit: &PackageAudit) {
    println!("Package format: {}", audit.package_format);
    println!("CNMT claimed title ID: {}", audit.title_id);
    println!("CNMT claimed version: {}", audit.version);
    println!("CNMT claimed type: {}", audit.meta_type);
    println!("NSP entries: {}", audit.package_entries);
    println!("Content referenced: {}", audit.referenced.len());
    for content in &audit.referenced {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            content.status.name(),
            content.hash_status.name(),
            content.header_status.name(),
            content.content_type,
            content.id,
            content.expected_size,
            content.package_filename.as_deref().unwrap_or("-")
        );
    }
    println!(
        "Size-matched: {} / {} (NOT hash/signature verified)",
        audit.count(MatchStatus::Present),
        audit.referenced.len()
    );
    if audit.headers_requested {
        println!(
            "Readable NCA header consistency: {} of {} entries (not authenticated)",
            audit.header_count(HeaderStatus::Consistent),
            audit.referenced.len()
        );
    } else {
        println!("NCA headers not checked (opt in with --headers)");
    }
    if audit.hashing_requested {
        println!(
            "SHA-256 matches against supplied CNMT: {} / {} (CNMT not authenticated)",
            audit.hash_count(HashStatus::Matched),
            audit.referenced.len()
        );
    } else {
        println!("SHA-256 not checked (opt in with --hash)");
    }
    println!("Unreferenced NCA entries: {}", audit.unreferenced_nca.len());
    for evidence in &audit.external_evidence {
        println!(
            "External evidence: {} ({})",
            evidence.kind, evidence.provenance
        );
        for (name, value) in &evidence.fields {
            println!("  {name}: {value}");
        }
    }
    println!("External metadata is NOT authenticated or proven to belong to this NSP.");
}

fn package_audit_json(audit: &PackageAudit) -> String {
    let mut out = format!(
        r#"{{"package_format":{},"title_id":{},"version":{},"meta_type":{},"metadata_source":"external_cnmt_unverified","package_entries":{},"content_count":{},"complete_by_size":{},"present":{},"missing":{},"size_mismatch":{},"compressed_unsupported":{},"ambiguous":{},"hashes_verified":false,"hashing_requested":{},"hashes_match_supplied_cnmt":{},"hash_matched":{},"hash_mismatched":{},"hash_unavailable":{},"headers_requested":{},"header_consistent":{},"header_type_mismatch":{},"header_size_mismatch":{},"header_unavailable":{},"header_malformed":{},"contents":["#,
        json_string(audit.package_format.name()),
        json_string(&audit.title_id),
        json_string(&audit.version),
        json_string(&audit.meta_type),
        audit.package_entries,
        audit.referenced.len(),
        audit.complete_by_size(),
        audit.count(MatchStatus::Present),
        audit.count(MatchStatus::Missing),
        audit.count(MatchStatus::SizeMismatch),
        audit.count(MatchStatus::CompressedUnsupported),
        audit.count(MatchStatus::Ambiguous),
        audit.hashing_requested,
        audit.all_hashes_match_supplied_cnmt(),
        audit.hash_count(HashStatus::Matched),
        audit.hash_count(HashStatus::Mismatched),
        audit.hash_count(HashStatus::Unavailable),
        audit.headers_requested,
        audit.header_count(HeaderStatus::Consistent),
        audit.header_count(HeaderStatus::TypeMismatch),
        audit.header_count(HeaderStatus::SizeMismatch),
        audit.header_count(HeaderStatus::Unavailable),
        audit.header_count(HeaderStatus::Malformed),
    );
    for (index, content) in audit.referenced.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write!(
            &mut out,
            r#"{{"id":{},"type":{},"expected_size":{},"expected_sha256":{},"actual_sha256":{},"hash_status":{},"header_status":{},"header_program_id":{},"header_content_type":{},"header_declared_size":{},"expected_filename":{},"package_filename":{},"package_size":{},"status":{}}}"#,
            json_string(&content.id),
            json_string(content.content_type),
            content.expected_size,
            json_string(&content.expected_sha256),
            content.actual_sha256.as_ref().map_or("null".to_string(), |s| json_string(s)),
            json_string(content.hash_status.name()),
            json_string(content.header_status.name()),
            content.header_program_id.as_ref().map_or("null".to_string(), |v| json_string(v)),
            content.header_content_type.as_ref().map_or("null".to_string(), |v| json_string(v)),
            content.header_declared_size.map_or("null".to_string(), |n| n.to_string()),
            json_string(&content.expected_filename),
            content.package_filename.as_ref().map_or("null".to_string(), |s| json_string(s)),
            content.package_size.map_or("null".to_string(), |n| n.to_string()),
            json_string(content.status.name()),
        ).expect("String write");
    }
    out.push_str(r#"],"unreferenced_nca":["#);
    for (index, file) in audit.unreferenced_nca.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str(&json_string(file));
    }
    out.push_str("],\"external_evidence\":[");
    for (index, evidence) in audit.external_evidence.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write!(
            &mut out,
            r#"{{"kind":{},"provenance":{},"linked_to_package":false,"fields":{{"#,
            json_string(evidence.kind),
            json_string(evidence.provenance),
        )
        .expect("String write");
        for (field_index, (key, value)) in evidence.fields.iter().enumerate() {
            if field_index != 0 {
                out.push(',');
            }
            write!(&mut out, "{}:{}", json_string(key), json_string(value)).expect("String write");
        }
        out.push_str("}}");
    }
    out.push_str("]}");
    out
}

#[derive(Default, Debug)]
struct TitleInventoryFlags {
    packages: bool,
    hash: bool,
    headers: bool,
    json: bool,
}

fn parse_title_inventory_flags(args: &[String]) -> Result<TitleInventoryFlags, String> {
    let mut flags = TitleInventoryFlags::default();
    for option in args {
        match option.as_str() {
            "--packages" if !flags.packages => flags.packages = true,
            "--hash" if !flags.hash => flags.hash = true,
            "--headers" if !flags.headers => flags.headers = true,
            "--json" if !flags.json => flags.json = true,
            _ => {
                return Err(format!(
                    "unknown or repeated titles inventory option: {option}"
                ))
            }
        }
    }
    if (flags.hash || flags.headers) && !flags.packages {
        return Err("--hash and --headers require --packages".into());
    }
    Ok(flags)
}

fn run_titles_inventory(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [root, flags @ ..] = args else {
        return Err(
            "usage: ninforge titles inventory <root> [--packages] [--hash] [--headers] [--json]"
                .into(),
        );
    };
    let flags = parse_title_inventory_flags(flags)?;
    let catalog = inventory_metadata_root_with_packages(
        Path::new(root),
        flags.packages,
        flags.hash,
        flags.headers,
    )?;
    if flags.json {
        println!("{}", title_inventory_json(&catalog));
    } else {
        print_title_inventory(&catalog);
    }
    Ok(())
}

fn print_title_inventory(catalog: &TitleInventory) {
    println!("External metadata bundles: {}", catalog.bundles_scanned);
    println!("Claimed application groups: {}", catalog.groups.len());
    if catalog.package_audits_requested {
        println!(
            "Designated NSP/XCI packages audited: {}",
            catalog.packages_audited
        );
        println!(
            "Bundles without designated package: {}",
            catalog.packages_missing
        );
    }
    println!(
        "Duplicate title/version/type sets: {}",
        catalog.version_collisions
    );
    for group in &catalog.groups {
        println!("Application group: {}", group.application_id);
        if let Some(version) = group.latest_application_version {
            println!("  highest supplied application CNMT version: {version}");
        }
        if let Some(version) = group.latest_patch_version {
            println!("  highest supplied patch CNMT version: {version}");
        }
        for record in &group.records {
            println!(
                "  {}\t{}\t{}\t{}\t{}",
                record.bundle,
                record.meta_type,
                record.title_id,
                record.version,
                record.atmosphere_cheat_build_id.as_deref().unwrap_or("-")
            );
            if let Some(ref audit) = record.package_audit {
                println!("    package {}: {} of {} content entries match by size; {} of {} match CNMT SHA-256 (checked: {})",
                    record.package_filename.as_deref().unwrap_or("-"),
                    audit.count(MatchStatus::Present), audit.referenced.len(),
                    audit.hash_count(HashStatus::Matched), audit.referenced.len(),
                    audit.hashing_requested);
            }
        }
        for collision in &group.version_collisions {
            println!(
                "  DUPLICATE\t{}\t{}\t{} files\tconflicting CNMT bytes: {}",
                collision.title_id,
                collision.version,
                collision.bundles.len(),
                collision.conflicting_content
            );
        }
    }
    println!("CNMT, NACP and NSO files are user-supplied and unverified.");
}

fn option_json(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), json_string)
}

/// Local title inventory JSON: each optional package audit retains its provenance.
/// This is a local inventory, not a server-backed latest-version feed.
fn title_inventory_json(catalog: &TitleInventory) -> String {
    let mut out = format!(
        r#"{{"schema_version":1,"source":"external_plaintext_metadata_unverified","bundles_scanned":{},"package_audits_requested":{},"packages_audited":{},"packages_missing":{},"application_groups":{},"version_collisions":{},"groups":["#,
        catalog.bundles_scanned,
        catalog.package_audits_requested,
        catalog.packages_audited,
        catalog.packages_missing,
        catalog.groups.len(),
        catalog.version_collisions,
    );
    for (i, group) in catalog.groups.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write!(
            &mut out,
            r#"{{"application_id":{},"latest_application_version":{},"latest_patch_version":{},"records":["#,
            json_string(&group.application_id),
            group.latest_application_version.map_or("null".into(), |v| v.to_string()),
            group.latest_patch_version.map_or("null".into(), |v| v.to_string()),
        ).expect("String write");
        for (j, record) in group.records.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            write!(
                &mut out,
                r#"{{"bundle":{},"title_id":{},"version":{},"meta_type":{},"application_group_id":{},"grouping_basis":{},"source_sha256":{},"content_count":{},"linked_application_id":{},"display_title":{},"display_version":{},"module_build_id":{},"atmosphere_cheat_build_id":{},"nacp_nso_link_verified":false,"package_filename":{},"package_audit":{}}}"#,
                json_string(&record.bundle),
                json_string(&record.title_id),
                record.version,
                json_string(&record.meta_type),
                json_string(&record.application_group_id),
                json_string(record.grouping_basis),
                json_string(&record.source_sha256),
                record.content_count,
                option_json(record.linked_application_id.as_deref()),
                option_json(record.display_title.as_deref()),
                option_json(record.display_version.as_deref()),
                option_json(record.module_build_id.as_deref()),
                option_json(record.atmosphere_cheat_build_id.as_deref()),
                option_json(record.package_filename.as_deref()),
                record.package_audit.as_ref().map_or_else(|| "null".to_string(), package_audit_json),
            ).expect("String write");
        }
        out.push_str(r#"],"version_collisions":["#);
        for (j, collision) in group.version_collisions.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            write!(
                &mut out,
                r#"{{"title_id":{},"version":{},"meta_type":{},"conflicting_content":{},"bundles":["#,
                json_string(&collision.title_id),
                collision.version,
                json_string(&collision.meta_type),
                collision.conflicting_content,
            ).expect("String write");
            for (index, name) in collision.bundles.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&json_string(name));
            }
            out.push_str("]}");
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    out
}

fn json_string(value: &str) -> String {
    let mut escaped = String::from("\"");
    for c in value.chars() {
        match c {
            '\"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c <= '\u{001f}' => {
                write!(&mut escaped, "\\u{:04x}", c as u32).expect("String write")
            }
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_inventory_flags_enforce_opt_in_expensive_reads() {
        let options = vec!["--packages".into(), "--hash".into(), "--json".into()];
        let flags = parse_title_inventory_flags(&options).unwrap();
        assert!(flags.packages && flags.hash && flags.json);
        assert!(!flags.headers);
        assert!(parse_title_inventory_flags(&["--hash".into()]).is_err());
        assert!(parse_title_inventory_flags(&["--headers".into()]).is_err());
        assert!(parse_title_inventory_flags(&["--packages".into(), "--packages".into()]).is_err());
        assert!(parse_title_inventory_flags(&["--unknown".into()]).is_err());
    }

    #[test]
    fn package_json_distinguishes_missing_unverified_metadata() {
        let report = PackageAudit {
            package_format: Format::SwitchNsp,
            title_id: "0123".into(),
            version: "65536".into(),
            meta_type: "patch".into(),
            package_entries: 1,
            hashing_requested: false,
            headers_requested: false,
            referenced: vec![ninforge::package::ContentMatch {
                id: "0011".into(),
                content_type: "program",
                expected_size: 7,
                expected_filename: "0011.nca".into(),
                package_filename: None,
                package_size: None,
                status: MatchStatus::Missing,
                expected_sha256: "00".repeat(32),
                actual_sha256: None,
                hash_status: HashStatus::NotChecked,
                header_status: HeaderStatus::NotChecked,
                header_program_id: None,
                header_content_type: None,
                header_declared_size: None,
            }],
            unreferenced_nca: vec!["other.nca".into()],
            external_evidence: vec![ninforge::package::ExternalEvidence {
                kind: "main_nso",
                provenance: "user_designated_main_unverified",
                fields: vec![("atmosphere_cheat_build_id".into(), "1234ABCD".into())],
            }],
        };
        let json = package_audit_json(&report);
        assert!(json.contains(r#""package_format":"Switch NSP/PFS0""#));
        assert!(json.contains(r#""metadata_source":"external_cnmt_unverified""#));
        assert!(json.contains(r#""package_filename":null"#));
        assert!(json.contains(r#""status":"missing""#));
        assert!(json.contains(r#""hashes_verified":false"#));
        assert!(json.contains(r#""hashing_requested":false"#));
        assert!(json.contains(r#""hash_status":"not_checked""#));
        assert!(json.contains(r#""headers_requested":false"#));
        assert!(json.contains(r#""header_status":"not_checked""#));
        assert!(json.contains(r#""unreferenced_nca":["other.nca"]"#));
        assert!(json.contains(r#""linked_to_package":false"#));
        assert!(json.contains(r#""provenance":"user_designated_main_unverified""#));
        assert!(json.contains(r#""atmosphere_cheat_build_id":"1234ABCD""#));
    }

    #[test]
    fn package_flags_are_explicit_and_reject_duplicates() {
        let args = vec![
            "--main-nso".into(),
            "main.nso".into(),
            "--hash".into(),
            "--headers".into(),
            "--json".into(),
            "--nacp".into(),
            "control.nacp".into(),
        ];
        let flags = parse_package_flags(&args).unwrap();
        assert_eq!(flags.nacp, Some("control.nacp"));
        assert_eq!(flags.main_nso, Some("main.nso"));
        assert!(flags.json);
        assert!(flags.hash);
        assert!(flags.headers);
        assert!(parse_package_flags(&["--nacp".into()]).is_err());
        assert!(parse_package_flags(&["--json".into(), "--json".into()]).is_err());
        assert!(parse_package_flags(&["--hash".into(), "--hash".into()]).is_err());
        assert!(parse_package_flags(&["--headers".into(), "--headers".into()]).is_err());
        assert!(parse_package_flags(&["--bogus".into()]).is_err());
    }

    #[test]
    fn json_escapes_control_characters() {
        assert_eq!(
            json_string("a\"\\\n\t\u{001f}"),
            "\"a\\\"\\\\\\n\\t\\u001f\""
        );
    }

    #[test]
    fn format_json_has_machine_readable_fields() {
        let r = Report {
            format: Format::Nes,
            bytes: 16,
            metadata: vec![("name".into(), "Test".into())],
            entries: vec![],
        };
        assert_eq!(report_json(&r, true), "{\"format\":\"NES iNES\",\"console\":\"nes\",\"size_bytes\":16,\"metadata\":{\"name\":\"Test\"},\"entries\":[]}");
    }
}
