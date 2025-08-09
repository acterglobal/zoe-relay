use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(ForwardCompatibleEnum)]
pub enum DuplicateDiscriminant {
    #[discriminant(1)]
    Variant1,
    #[discriminant(1)]  // Duplicate!
    Variant2,
    Unknown { discriminant: u32, data: Vec<u8> },
}