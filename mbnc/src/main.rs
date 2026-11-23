use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{BufRead, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "mbnc", version, about = "A bouncer for MUDs, MOOs and other M*s")]
struct Cli {
    /// Path to the config file.
    #[arg(short, long, default_value = "mbnc.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the bouncer (default).
    Run,
    /// Read a password on stdin and print an argon2 hash for `password_hash`.
    HashPassword,
    /// Parse and validate the config file, then exit.
    CheckConfig,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Run) {
        Cmd::HashPassword => hash_password(),
        Cmd::CheckConfig => {
            mbnc::config::Config::load(&cli.config)?;
            println!("{}: OK", cli.config.display());
            Ok(())
        }
        Cmd::Run => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            let cfg = mbnc::config::Config::load(&cli.config)?;
            tokio::runtime::Runtime::new()?.block_on(mbnc::run(cfg))
        }
    }
}

fn hash_password() -> Result<()> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use rand_core::OsRng;
    eprint!("Password (will echo; or pipe it in): ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let pw = line.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(!pw.is_empty(), "empty password");
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2::Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{hash}");
    Ok(())
}
