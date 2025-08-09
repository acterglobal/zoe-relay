use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(ForwardCompatibleEnum)]
#[forward_compatible(unknown_variant = "Variant1")]  // Conflicts with existing variant!
pub enum ConflictingUnknownName {
    #[discriminant(1)]
    Variant1,
    Unknown { discriminant: u32, data: Vec<u8> },
}