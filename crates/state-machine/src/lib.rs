//! Digital Group Assistant (DGA) Protocol
//!
//! A PDA-like application framework using the wire-protocol to send activity-events
//! as messages between participants to organize state machines of organizational objects.

pub mod error;
pub mod group;
pub mod state;

#[cfg(test)]
mod tests;

pub use error::*;
pub use group::*;
// Re-export specific types from state module, excluding GroupState which is now in app-primitives
pub use state::{GroupEncryptionState, GroupStateSnapshot};

// Re-export unified group state types from app-primitives
pub use zoe_app_primitives::{
    GroupMember, GroupMembership, GroupState, GroupStateError, GroupStateResult,
};

// Re-export crypto functionality from wire-protocol
pub use zoe_wire_protocol::{
    ChaCha20Poly1305Content, EncryptionKey, MnemonicPhrase, generate_ed25519_from_mnemonic,
    recover_ed25519_from_mnemonic,
};

// Re-export bip39 for tests and examples
pub use zoe_wire_protocol::bip39;

// Re-export common group types from app-primitives for convenience
pub use zoe_app_primitives::{
    EncryptionSettings, GroupActivityEvent, GroupKeyInfo, GroupPermissions, GroupSettings,
    Permission, roles::GroupRole,
};
