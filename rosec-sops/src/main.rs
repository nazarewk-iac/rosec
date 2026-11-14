//! `rosec-sops`: inspect and resolve conflicts of a sops-backed rosec store.
//!
//! The provider writes a plaintext, secret-free marker when a write archives a
//! divergent copy of an item. This binary lists, shows and resolves those
//! markers without the daemon and without decrypting anything. See
//! [`rosec_sops::conflicts`] and `rosec-sops/README.md`.

use clap::Parser;

fn main() -> std::process::ExitCode {
    let cli = rosec_sops::cli::Cli::parse();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start the async runtime: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    match runtime.block_on(rosec_sops::cli::run(cli)) {
        0 => std::process::ExitCode::SUCCESS,
        code => std::process::ExitCode::from(code as u8),
    }
}
