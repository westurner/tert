//! vc binary - sign and verify Verifiable Credential (JSON/YAML-LD) documents.

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    process::exit(tert::vc::cli_main(&args));
}
