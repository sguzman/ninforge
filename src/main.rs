//! Standalone binary for the Ninforge library. Pure std: no runtime dependencies.

use ninforge::{extract_entry, inspect, Entry, Format, Report};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::path::Path;

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
        [cmd] if cmd == "--version" || cmd == "-V" => println!("ninforge {}", env!("CARGO_PKG_VERSION")),
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
            require_pfs0(&report)?;
            for entry in &report.entries { println!("{}\t{}", entry.size, entry.name); }
        }
        [cmd, file, flag] if cmd == "list" && flag == "--json" => {
            let report = inspect(&mut File::open(file)?)?;
            require_pfs0(&report)?;
            println!("{}", report_json(&report, true));
        }
        [cmd, file] if cmd == "verify" => {
            let report = inspect(&mut File::open(file)?)?;
            require_pfs0(&report)?;
            println!("OK: PFS0 table and {} entry bounds are structurally valid (not a hash/signature check)", report.entries.len());
        }
        [cmd, input, entry_name, output] if cmd == "extract" => {
            let mut archive = File::open(input)?;
            let report = inspect(&mut archive)?;
            require_pfs0(&report)?;
            let matches: Vec<&Entry> = report.entries.iter().filter(|entry| entry.name == *entry_name).collect();
            let [entry] = matches.as_slice() else {
                return Err(format!("expected exactly one entry named {entry_name:?}, found {}", matches.len()).into());
            };
            // Explicit output is never derived from a potentially malicious archive filename.
            // create_new rejects existing paths and symlinks rather than overwriting a save.
            let destination = Path::new(output);
            let mut sink = OpenOptions::new().write(true).create_new(true).open(destination)?;
            let result = extract_entry(&mut archive, entry, &mut sink)
                .and_then(|_| sink.sync_all());
            if let Err(error) = result {
                drop(sink);
                let _ = fs::remove_file(destination);
                return Err(error.into());
            }
            println!("Extracted {} bytes to {}", entry.size, destination.display());
        }
        [] => usage(),
        _ => return Err("invalid arguments; run 'ninforge help'".into()),
    }
    Ok(())
}

fn require_pfs0(report: &Report) -> Result<(), Box<dyn std::error::Error>> {
    if report.format != Format::SwitchNsp {
        return Err("this operation currently supports only PFS0/NSP containers".into());
    }
    Ok(())
}

fn usage() {
    println!("\
Ninforge {} - Nintendo file inspection (read-only by default)

Usage:
  ninforge info <file> [--json]            Detect format and inspect header
  ninforge inspect <file> [--json]         Alias for info
  ninforge list <file> [--json]            List Switch NSP/PFS0 entries
  ninforge verify <file>                   Validate PFS0 table and entry bounds
  ninforge extract <file> <entry> <out>    Extract one PFS0 entry; never overwrite
  ninforge help                            Show this help

Limitations:
  No decryption, save editing, signing, repacking, or full cryptographic verify.
  NSP/PFS0 listing does not require Nintendo keys; many encrypted inner files do.
", env!("CARGO_PKG_VERSION"));
}

fn print_report(report: &Report, list: bool) {
    println!("Format: {}", report.format);
    println!("Console: {}", report.format.console());
    println!("Bytes: {}", report.bytes);
    for (key, value) in &report.metadata { println!("{key}: {value}"); }
    if list {
        for entry in &report.entries { println!("{}\t{}", entry.size, entry.name); }
    }
}

fn report_json(report: &Report, include_entries: bool) -> String {
    let mut text = format!(
        "{{\"format\":{},\"console\":{},\"size_bytes\":{},\"metadata\":{{",
        json_string(report.format.name()), json_string(report.format.console()), report.bytes,
    );
    for (i, (key, value)) in report.metadata.iter().enumerate() {
        if i != 0 { text.push(','); }
        write!(&mut text, "{}:{}", json_string(key), json_string(value)).expect("String write");
    }
    text.push('}');
    if include_entries {
        text.push_str(",\"entries\":[");
        for (i, entry) in report.entries.iter().enumerate() {
            if i != 0 { text.push(','); }
            write!(&mut text, "{{\"name\":{},\"offset\":{},\"size_bytes\":{}}}",
                json_string(&entry.name), entry.offset, entry.size).expect("String write");
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
            c if c <= '\u{001f}' => write!(&mut escaped, "\\u{:04x}", c as u32).expect("String write"),
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
        assert_eq!(json_string("a\"\\\n\t\u{001f}"), "\"a\\\"\\\\\\n\\t\\u001f\"");
    }

    #[test]
    fn format_json_has_machine_readable_fields() {
        let r = Report { format: Format::Nes, bytes: 16, metadata: vec![("name".into(), "Test".into())], entries: vec![] };
        assert_eq!(report_json(&r, true), "{\"format\":\"NES iNES\",\"console\":\"nes\",\"size_bytes\":16,\"metadata\":{\"name\":\"Test\"},\"entries\":[]}");
    }
}
