use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZoeServices {
    Messages = 10,
    Blob = 11,
}

impl fmt::Display for ZoeServices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZoeServices::Messages => write!(f, "Messages"),
            ZoeServices::Blob => write!(f, "Blob"),
        }
    }
}

impl TryFrom<u8> for ZoeServices {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            10 => Ok(ZoeServices::Messages),
            11 => Ok(ZoeServices::Blob),
            _ => Err(()),
        }
    }
}
