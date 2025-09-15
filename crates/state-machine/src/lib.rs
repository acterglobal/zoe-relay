//! Digital Group Assistant (DGA) Protocol
//!
//! A PDA-like application framework using the wire-protocol to send activity-events
//! as messages between participants to organize state machines of organizational objects.

pub mod error;
pub mod group;
pub mod state;

#[cfg(test)]
mod tests;

pub use group::{GroupDataUpdate, GroupManager};
pub use state::{GroupSession, GroupStateSnapshot};
