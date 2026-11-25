//! Reader side of the MIFARE DUOX (MF3E(H)x3) protocol: [`Card`].
//!
//! # Design
//!
//! `Card<T: Transport>` owns its transport and is generic over it. Static dispatch keeps the
//! tests simple (a `Card<MockTransport>` lets the test inspect the transport afterwards through
//! [`Card::transport`]) while `Card<Box<dyn Transport>>` works for applications that choose the
//! reader at run time, because `Box<dyn Transport>` implements [`Transport`] too.
//!
//! All card I/O is synchronous; every command is a `&mut self` method returning
//! [`crate::error::Result`].
//!
//! # Protocol invariants kept by this layer
//!
//! * Any error returned by a command ends the authentication (the card does the same), restarts
//!   Transaction MAC Input recording and leaves [`Card::is_authenticated`] false. Do not probe
//!   the card with speculative commands while authenticated; use cached file settings.
//! * `SelectApplication` and `ISOSelectFile` of a DF end the authentication.
//! * The command counter (CmdCtr) increases once per native command while authenticated,
//!   including commands sent in [`CommMode::Plain`]. It does not increase for additional frames
//!   or for the three proximity-check commands. CreateDelegatedApplication (two frames) counts once.
//! * The command header is never encrypted; only the data field is, in [`CommMode::Full`].
//! * ECC sessions have TI = 00000000 and an access-condition bitmap (`acmap`); AES sessions grant
//!   exactly the authenticated key number. Bit 7 of key / file numbers addresses the secondary
//!   of two selected applications.
//! * Transaction MAC Input is recorded from the commands actually sent through the typed data
//!   methods. [`Card::native_raw`] and [`Card::apdu_raw`] bypass recording and secure messaging.
//! * ISO 7816-4 file commands and EV charging commands are plain and only valid while not
//!   authenticated.
//!
//! Section numbers in comments refer to the NXP MIFARE DUOX data sheet Rev. 1.2.

pub mod apps;
pub mod auth_aes;
pub mod auth_ecc;
pub mod config;
pub mod crypto_req;
pub mod data;
pub mod evcharge;
pub mod files;
pub mod gpio;
pub mod iso;
pub mod keys;
pub mod proximity;
pub mod secure_messaging;
pub mod session;
#[cfg(test)]
mod sm_tests;
#[cfg(test)]
pub(crate) mod testkit;
pub mod tlv;
pub mod txn;
pub mod types;

use crate::crypto::Session;
use crate::transport::Transport;
pub use crate::txmac::Tmi;

pub use apps::{AppSpec, DelegatedAppSpec, DelegatedInfo, DelegatedKeys, DfName, KeySetConfig};
pub use auth_aes::AesAuthInfo;
pub use auth_ecc::{CertSigOrder, EccAuthOptions, EccAuthResult, InternalAuthResult, OriginalityResult};
pub use config::{StorageSize, VersionInfo};
pub use crypto_req::SignInput;
pub use data::ModeSel;
pub use files::{
    CrlChange, CrlSettings, DataFileSpec, FileSettings, FileSettingsChange, RecordFileSpec, RecordSettings,
    TmacFileSpec, TmacSettings, ValueFileSpec, ValueSettings,
};
pub use gpio::{GpioControl, GpioLevel, GpioOperation, GpioStatus};
pub use iso::{FastUid, IsoSelect};
pub use keys::{
    CaRootKeyInfo, CaRootKeySpec, ChangeKeySpec, EccKeyInfo, KeyPairOp, KeyPairSpec, KeySetInfo, KeySettings,
};
pub use proximity::ProximityResult;
pub use secure_messaging::{build_apdu, Le};
pub use session::{AuthKind, AuthSummary};
pub use txn::CommitResult;
pub use types::{command_name, Aid, AccessRight, AccessRights, CommMode, FileType, Status};

/// Which application(s) are currently selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// `Some(Aid::PICC)` at PICC level; `None` after an ISO selection the library cannot name.
    pub primary: Option<Aid>,
    /// Secondary application of a two-application SelectApplication.
    pub secondary: Option<Aid>,
}

type LogHook = Box<dyn FnMut(&str) + Send>;

/// A DUOX card behind a [`Transport`].
pub struct Card<T: Transport> {
    pub(crate) transport: T,
    pub(crate) session: Option<Session>,
    pub(crate) auth_info: Option<AesAuthInfo>,
    pub(crate) selection: Selection,
    pub(crate) max_native_frame: usize,
    pub(crate) uid: Vec<u8>,
    pub(crate) tmi: Tmi,
    /// The application holding the TransactionMAC file is the secondary one.
    pub(crate) tm_secondary: bool,
    pub(crate) log: Option<LogHook>,
}

impl<T: Transport> Card<T> {
    /// Wrap a transport. The card is assumed to be at PICC level, not authenticated.
    pub fn new(transport: T) -> Self {
        Card {
            transport,
            session: None,
            auth_info: None,
            selection: Selection { primary: Some(Aid::PICC), secondary: None },
            max_native_frame: 55,
            uid: Vec::new(),
            tmi: Tmi::default(),
            tm_secondary: false,
            log: None,
        }
    }

    /// Power the card through the transport and reset all protocol state. Returns the ATR.
    pub fn connect(&mut self) -> crate::error::Result<Vec<u8>> {
        let atr = self.transport.connect()?;
        self.reset_state();
        // A PC/SC reset does not always clear a card's authenticated session (seen with an OMNIKEY
        // 5022 and a card left authenticated by an earlier process), so end any stale session
        // explicitly. Selecting the PICC is harmless and ends authentication. Best effort only.
        let _ = self.select_application(Aid::PICC, None);
        self.reset_state();
        Ok(atr)
    }

    pub fn disconnect(&mut self) {
        if self.session.is_some() {
            let _ = self.select_application(Aid::PICC, None); // leave the card unauthenticated
        }
        self.transport.disconnect();
        self.reset_state();
    }

    fn reset_state(&mut self) {
        self.session = None;
        self.auth_info = None;
        self.selection = Selection { primary: Some(Aid::PICC), secondary: None };
        self.tmi = Tmi::default();
        self.tm_secondary = false;
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Install a callback that receives one line per command ("-- Name [mode]"). Key material
    /// is never included. APDU level tracing is installed on the transport instead.
    pub fn set_log(&mut self, hook: Option<Box<dyn FnMut(&str) + Send>>) {
        self.log = hook;
    }

    pub(crate) fn log_line(&mut self, line: &str) {
        if let Some(h) = self.log.as_mut() {
            h(line);
        }
    }

    /// Currently selected application(s).
    pub fn selection(&self) -> Selection {
        self.selection
    }

    /// UID as last read by GetVersion / GetCardUID / fast UID retrieval (empty if unknown).
    pub fn uid(&self) -> &[u8] {
        &self.uid
    }

    /// Native bytes per frame used when chaining WriteData / WriteRecord / UpdateRecord.
    pub fn max_native_frame(&self) -> usize {
        self.max_native_frame
    }

    /// Change the chaining frame size (default 55 bytes; larger values need fewer round trips when
    /// the reader and card accept bigger frames). Clamped to 16..=255.
    pub fn set_max_native_frame(&mut self, n: usize) {
        self.max_native_frame = n.clamp(16, 255);
    }
}
