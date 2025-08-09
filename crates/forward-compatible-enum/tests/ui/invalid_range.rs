use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(ForwardCompatibleEnum)]
#[forward_compatible(range = "invalid")]  // Invalid range format!
pub enum InvalidRange {
    #[discriminant(1)]
    Variant1,
    Unknown { discriminant: u32, data: Vec<u8> },
}