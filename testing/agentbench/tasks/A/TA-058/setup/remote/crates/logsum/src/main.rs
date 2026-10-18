//! logsum: requests and bytes per HTTP status, over access logs.
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process;

/// (status, bytes) of one access-log line in the common log format.
fn parse(line: &str) -> (u16, u64) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let status: u16 = fields[8].parse().unwrap();
    let bytes: u64 = if fields[9] == "-" { 0 } else { fields[9].parse().unwrap() };
    (status, bytes)
}

fn main() {
    let paths: Vec<String> = env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: logsum LOG...");
        process::exit(2);
    }
    let mut table: BTreeMap<u16, (u64, u64)> = BTreeMap::new();
    let skipped = 0;
    for p in &paths {
        let text = fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("logsum: {p}: {e}");
            process::exit(1)
        });
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let (status, bytes) = parse(line);
            let e = table.entry(status).or_insert((0, 0));
            e.0 += 1;
            e.1 += bytes;
        }
    }
    println!("{:<7} {:>9} {:>12}", "status", "requests", "bytes");
    for (s, (n, b)) in &table {
        println!("{:<7} {:>9} {:>12}", s, n, b);
    }
    println!("skipped {skipped}");
}
