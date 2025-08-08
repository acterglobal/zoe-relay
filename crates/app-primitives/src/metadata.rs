use serde::{Deserialize, Serialize};

use crate::Image;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Metadata {
    Generic(String, String),
    Avatar(Image),
    Background(Image),
    Description(String),
    Website(String),
    Email(String),
    Phone(String),
    Address(String),
    Social(String, String),
}
