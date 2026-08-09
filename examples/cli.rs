use clap::Parser;
use std::io::BufRead;
use std::path::PathBuf;
use tdata_rs::TDesktop;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to tdata folder (usually ~/.local/share/TelegramDesktop/tdata)
    #[arg(default_value = "")]
    path: String,

    /// Prompt for the local passcode without echoing it
    #[arg(long, conflicts_with = "passcode_stdin")]
    prompt_passcode: bool,

    /// Read the local passcode from stdin (first line)
    #[arg(long, conflicts_with = "prompt_passcode")]
    passcode_stdin: bool,

    /// Show the legacy tdata-rs-specific credential blob (not a grammers session format)
    #[arg(long = "show-legacy-session", alias = "show-session", hide = true)]
    show_legacy_session: bool,

    /// Show full auth keys (authentication credentials)
    #[arg(long)]
    show_keys: bool,

    /// Show the local storage path and Telegram user identifiers
    #[arg(long)]
    show_identifiers: bool,
}

fn read_passcode(args: &Args) -> anyhow::Result<Option<String>> {
    if args.prompt_passcode {
        let passcode = rpassword::prompt_password("Telegram Desktop local passcode: ")?;
        anyhow::ensure!(!passcode.is_empty(), "no passcode was entered");
        return Ok(Some(passcode));
    }

    if args.passcode_stdin {
        let mut passcode = String::new();
        std::io::stdin().lock().read_line(&mut passcode)?;
        while passcode.ends_with('\n') || passcode.ends_with('\r') {
            passcode.pop();
        }
        anyhow::ensure!(!passcode.is_empty(), "stdin did not contain a passcode");
        return Ok(Some(passcode));
    }

    Ok(None)
}

fn main() -> anyhow::Result<()> {
    // Setup logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Determine path
    let path = if args.path.is_empty() {
        let home = std::env::var("HOME")?;
        PathBuf::from(home).join(".local/share/TelegramDesktop/tdata")
    } else {
        PathBuf::from(&args.path)
    };

    if args.show_identifiers {
        println!("📂 Reading tdata from: {:?}", path);
    } else {
        println!("📂 Reading tdata from: [redacted; use --show-identifiers to reveal]");
    }

    if args.show_legacy_session || args.show_keys || args.show_identifiers {
        eprintln!(
            "WARNING: requested private account data will be written to stdout; do not capture or share it."
        );
    }

    // Load TDesktop. Never keep the supplied passcode in the parsed object.
    let tdata = if let Some(mut passcode) = read_passcode(&args)? {
        let result = TDesktop::from_path_with_passcode(&path, &passcode);
        passcode.zeroize();
        result?
    } else {
        TDesktop::from_path(&path)?
    };

    println!("✅ Successfully loaded TDesktop storage!");
    println!("   App Version: {}", tdata.app_version());
    println!(
        "   Passcode:    {}",
        if tdata.has_passcode() { "YES" } else { "NO" }
    );
    println!("   Accounts:    {}", tdata.accounts().len());
    println!();

    for (i, account) in tdata.accounts().iter().enumerate() {
        println!(
            "👤 Account #{} (Index {})",
            i.saturating_add(1),
            account.index()
        );
        if args.show_identifiers {
            println!("   User ID:   {}", account.user_id());
        } else {
            println!("   User ID:   [redacted; use --show-identifiers to reveal]");
        }
        println!("   DC ID:     {}", account.dc_id());

        if args.show_legacy_session {
            println!(
                "   Legacy credential blob: {}",
                account.to_legacy_session_string()?
            );
        } else {
            println!("   Grammers:  SessionData conversion available");
        }

        if args.show_keys {
            println!("   Auth Key:  {}", hex::encode(account.auth_key_bytes()));
        } else {
            println!("   Auth Key:  [redacted; use --show-keys to reveal]");
        }
        println!();
    }

    Ok(())
}
