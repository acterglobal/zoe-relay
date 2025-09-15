//! Digital Group Assistant (DGA) Protocol
//!
//! A PDA-like application framework using the wire-protocol to send activity-events
//! as messages between participants to organize state machines of organizational objects.

pub mod error;
pub mod group;
pub mod state;

#[cfg(test)]
mod tests;

// Note: Client crate is allowed to re-export from state-machine
// but state-machine itself should not re-export
