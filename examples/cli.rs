use clap::Parser;
use tdata_rs::TDesktop;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to tdata folder (usually ~/.local/share/TelegramDesktop/tdata)
    #[arg(default_value = "")]
    path: String,

    /// Local passcode (if set)
    #[arg(short, long)]
    passcode: Option<String>,

    /// Show full auth keys (be careful sharing output!)
    #[arg(long)]
    show_keys: bool,
}

fn main() -> anyhow::Result<()> {
    // Setup logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Determine path
    let path = if args.path.is_empty() {
        let home = std::env::var("HOME")?;
        PathBuf::from(home)
            .join(".local/share/TelegramDesktop/tdata")
    } else {
        PathBuf::from(&args.path)
    };

    println!("📂 Reading tdata from: {:?}", path);

    // Load TDesktop
    let tdata = if let Some(passcode) = args.passcode {
        TDesktop::from_path_with_passcode(&path, &passcode)?
    } else {
        TDesktop::from_path(&path)?
    };

    println!("✅ Successfully loaded TDesktop storage!");
    println!("   App Version: {}", tdata.app_version());
    println!("   Passcode:    {}", if tdata.has_passcode() { "YES" } else { "NO" });
    println!("   Accounts:    {}", tdata.accounts().len());
    println!();

    for (i, account) in tdata.accounts().iter().enumerate() {
        println!("👤 Account #{} (Index {})", i + 1, account.index());
        println!("   User ID:   {}", account.user_id());
        println!("   DC ID:     {}", account.dc_id());
        
        // Generate Grammers session string
        if let Ok(session) = account.to_session_string() {
            println!("   Session:   {}", session);
        }

        if args.show_keys {
            println!("   Auth Key:  {}", hex::encode(account.auth_key_bytes()));
        }
        println!();
    }

    Ok(())
}
