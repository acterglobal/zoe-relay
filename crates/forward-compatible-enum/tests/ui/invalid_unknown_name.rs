use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(ForwardCompatibleEnum)]
#[forward_compatible(unknown_variant = "123Invalid")]  // Invalid identifier!
pub enum InvalidUnknownName {
    #[discriminant(1)]
    Variant1,
    Unknown { discriminant: u32, data: Vec<u8> },
}