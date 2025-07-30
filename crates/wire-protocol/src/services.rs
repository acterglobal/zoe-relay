use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZoeServices {
    Messages = 10,
    Blob = 11,
}
