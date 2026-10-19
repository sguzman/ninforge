//! Standalone binary for the Ninforge library. Pure std: no runtime dependencies.

use ninforge::cnmt::inspect_cnmt;
use ninforge::nacp::inspect_nacp;
use ninforge::nca::inspect_decrypted_nca;
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
            require_sections(&report)?;
            println!("OK: {} header and {} region bounds are structurally valid (not a hash/signature check)", report.format, report.entries.len());
        }
        [cmd, sub, root] if cmd == "saves" && sub == "scan" => save_scan(Path::new(root), false)?,
        [cmd, sub, root, flag] if cmd == "saves" && sub == "scan" && flag == "--json" => {
            save_scan(Path::new(root), true)?
        }
        [cmd, sub, source, destination] if cmd == "saves" && sub == "backup" => {
            let copied = saves::backup(Path::new(source), Path::new(destination))?;
            println!("Backed up {copied} bytes to {destination} (source untouched)");
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
  ninforge verify <file>                   Validate NSP/HFS0/XCI/DS bounds
  ninforge extract <file> <entry> <out>    Extract one entry/section; no overwrite
  ninforge scan <directory> [--json]       Recursive recognized-file inventory
  ninforge nacp info <file> [--json]       Read decrypted control.nacp metadata
  ninforge nca info <file> [--json]        Inspect already-decrypted NCA header
  ninforge cnmt info <file> [--json]       Parse standalone plaintext CNMT
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
