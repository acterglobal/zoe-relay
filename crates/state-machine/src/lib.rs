//! Digital Group Assistant (DGA) Protocol
//!
//! A PDA-like application framework using the wire-protocol to send activity-events
//! as messages between participants to organize state machines of organizational objects.

pub mod app_manager;
pub mod apps;
pub mod error;
pub mod execution;
pub mod group;
pub mod index;
pub mod messages;
pub mod state;

#[cfg(test)]
mod tests;
