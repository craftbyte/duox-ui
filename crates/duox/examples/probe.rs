//! Read-only probe of a DUOX card in a PC/SC reader.
//!
//!     cargo run -p duox --example probe -- [reader-substring]
//!
//! Authenticates at PICC level with the factory all-zero AES-128 key (key 0) and reads
//! version, UID, key settings, applications and free memory. It changes nothing on the card
//! (the authentication only bumps the card's authentication counter).

use duox::card::{Aid, Card};
use duox::transport::{list_readers, PcscTransport};
use duox::transport::{TraceDir, Transport};

fn step<T>(name: &str, r: duox::Result<T>, show: impl FnOnce(&T) -> String) -> Option<T> {
    match r {
        Ok(v) => {
            println!("{name:<22} {}", show(&v));
            Some(v)
        }
        Err(e) => {
            println!("{name:<22} FAILED: {e}");
            None
        }
    }
}

fn main() {
    let readers = list_readers().unwrap_or_else(|e| {
        eprintln!("PC/SC: {e}");
        std::process::exit(1)
    });
    println!("readers: {readers:?}");
    let want = std::env::args().nth(1).unwrap_or_default().to_lowercase();
    let Some(name) = readers.iter().find(|r| r.to_lowercase().contains(&want)) else {
        eprintln!("no matching reader");
        std::process::exit(1)
    };
    println!("using {name}");

    let mut t = PcscTransport::new(name.clone());
    t.set_trace(Some(Box::new(|d, b| {
        let arrow = if d == TraceDir::Tx { ">>" } else { "<<" };
        println!("   {arrow} {}", hex::encode_upper(b));
    })));
    let mut card = Card::new(t);
    let Some(_) = step("connect (ATR)", card.connect(), |a| hex::encode_upper(a)) else { return };

    step("GetVersion", card.get_version(), |v| format!("{v:#?}"));
    step("select PICC", card.select_application(Aid::PICC, None), |s| format!("rc={s:02X}"));
    let key = [0u8; 16];
    if step("auth key0 (AES128)", card.authenticate_ev2_first(0, &key, &[]), |a| {
        format!("TI={} PDcap2={}", hex::encode_upper(a.ti), hex::encode_upper(&a.pd_cap2))
    })
    .is_some()
    {
        println!("session: {}", card.state_text());
        step("GetCardUID", card.get_card_uid(), |u| hex::encode_upper(u));
        step("GetKeySettings", card.get_key_settings(), |k| format!("{k:?}"));
        step("GetKeyVersion 0", card.get_key_version(0, None), |v| hex::encode_upper(v));
        step("GetApplicationIDs", card.get_application_ids(), |a| format!("{a:?}"));
        step("GetDFNames", card.get_df_names(), |a| format!("{a:?}"));
        step("FreeMem", card.free_mem(), |m| format!("{m} bytes"));
        step("GetFileIDs (PICC)", card.get_file_ids(), |f| format!("{f:02X?}"));
        println!("session: {}", card.state_text());
    }
    card.disconnect();
}
