//! did-agent binary - ssh-agent-style Ed25519 did:key signing agent.

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    process::exit(tert::did_agent::cli_main(&args));
}
