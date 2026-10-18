//! stampede: a load generator for the matchmaking service.

const BUILD: &str = "5f1c";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => println!("stampede {} (build {BUILD})", env!("CARGO_PKG_VERSION")),
        Some("--build-info") => {
            let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
            println!("profile: {profile}");
        }
        Some(n) => match n.parse::<u32>() {
            Ok(clients) => {
                let mut total: u64 = 0;
                for c in 0..clients {
                    total = total.wrapping_mul(6364136223846793005).wrapping_add(u64::from(c));
                }
                println!("simulated {clients} clients, checksum {total:x}");
            }
            Err(_) => {
                eprintln!("usage: stampede [--version | --build-info | CLIENTS]");
                std::process::exit(2);
            }
        },
        None => println!("stampede: pass a number of clients"),
    }
}
