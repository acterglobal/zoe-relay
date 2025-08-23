//! Inbox system for asynchronous message protocols
//!
//! This module provides the infrastructure for PQXDH-based inboxes that allow
//! asynchronous secure communication establishment.

pub mod pqxdh;

pub use pqxdh::*;
