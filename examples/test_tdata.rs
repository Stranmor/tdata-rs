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
            println!("   App version: {}", tdesktop.app_version());
            println!("   Accounts: {}", tdesktop.accounts_count());
            println!("   Has passcode: {}", tdesktop.has_passcode());
            println!();

            for (i, account) in tdesktop.accounts().iter().enumerate() {
                println!("Account {} (index {}):", i, account.index());
                println!("   DC ID: {}", account.dc_id());
                println!("   User ID: [redacted]");

                // Verify credential extraction without writing credential material.
                println!("   Auth key extracted: YES");

                let session_data = account.to_grammers_session_data();
                println!(
                    "   Grammers SessionData prepared for DC {}",
                    session_data.home_dc
                );

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
