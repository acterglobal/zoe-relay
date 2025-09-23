//! Digital Group Assistant (DGA) Protocol
//!
//! A PDA-like application framework using the wire-protocol to send activity-events
//! as messages between participants to organize state machines of organizational objects.

pub mod app_manager;
pub mod apps;
pub mod error;
pub mod execution;
pub mod group;
pub mod messages;
pub mod state;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration_test;

#[cfg(test)]
mod join_group_test;

// Note: Client crate is allowed to re-export from state-machine
// but state-machine itself should not re-export
