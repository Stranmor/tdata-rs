//! Test binary for tdata-rs

use tdata_rs::TDesktop;

fn main() {
    // Configure tracing for debug output
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("=== tdata-rs Test ===\n");

    // Try loading from default location
    match TDesktop::from_default() {
        Ok(tdesktop) => {
            println!("✅ Successfully loaded tdata!");
            println!("   Path: {:?}", tdesktop.base_path());
            println!("   App version: {}", tdesktop.app_version());
            println!("   Accounts: {}", tdesktop.accounts_count());
            println!("   Has passcode: {}", tdesktop.has_passcode());
            println!();

            for (i, account) in tdesktop.accounts().iter().enumerate() {
                println!("Account {} (index {}):", i, account.index());
                println!("   DC ID: {}", account.dc_id());
                println!("   User ID: {}", account.user_id());

                // Show first 8 bytes of auth key (for verification)
                let key = account.auth_key_bytes();
                println!("   Auth key (first 8 bytes): {:02x?}", &key[..8]);

                // Try converting to session string
                match account.to_session_string() {
                    Ok(session_str) => {
                        println!(
                            "   Session string (first 32 chars): {}...",
                            &session_str[..32.min(session_str.len())]
                        );
                    }
                    Err(e) => {
                        println!("   ❌ Failed to create session string: {}", e);
                    }
                }

                println!();
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to load tdata: {}", e);
            eprintln!();
            eprintln!("This could mean:");
            eprintln!("  - Telegram Desktop is not installed");
            eprintln!("  - tdata is password-protected (use from_path_with_passcode)");
            eprintln!("  - tdata format has changed");
            std::process::exit(1);
        }
    }

    println!("=== Test Complete ===");
}
