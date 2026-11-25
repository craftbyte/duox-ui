//! One module per tab. See ARCHITECTURE.md ("Writing a tab").

pub mod auth;
pub mod card;
pub mod crl;
pub mod delegated;
pub mod features;
pub mod pki;
pub mod sdm;
pub mod tools;
pub mod transactions;

/// The tabs, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TabId {
    Card,
    Auth,
    Pki,
    Crl,
    Sdm,
    Delegated,
    Transactions,
    Features,
    Tools,
}

impl TabId {
    pub const ALL: [TabId; 9] = [
        TabId::Card,
        TabId::Auth,
        TabId::Pki,
        TabId::Crl,
        TabId::Sdm,
        TabId::Delegated,
        TabId::Transactions,
        TabId::Features,
        TabId::Tools,
    ];

    pub fn title(self) -> &'static str {
        match self {
            TabId::Card => "Card",
            TabId::Auth => "Authenticate",
            TabId::Pki => "CAs & certificates",
            TabId::Crl => "CRL",
            TabId::Sdm => "SDM",
            TabId::Delegated => "Delegated apps",
            TabId::Transactions => "Transactions",
            TabId::Features => "ISO / GPIO / EV",
            TabId::Tools => "Configuration & tools",
        }
    }
}
