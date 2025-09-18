use forward_compatible_enum::ForwardCompatibleEnum;

use crate::file::Image;
#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "frb-api", frb(non_opaque))]
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum Metadata {
    #[discriminant(0)]
    Generic { key: String, value: String },

    #[discriminant(10)]
    Description(String),

    #[discriminant(20)]
    Avatar(Image),
    #[discriminant(21)]
    Background(Image),
    #[discriminant(30)]
    Website(String),
    #[discriminant(40)]
    Email(String),
    #[discriminant(41)]
    Phone(String),
    #[discriminant(50)]
    Address(String),
    #[discriminant(60)]
    Social { platform: String, handle: String },

    /// Unknown metadata type for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}
