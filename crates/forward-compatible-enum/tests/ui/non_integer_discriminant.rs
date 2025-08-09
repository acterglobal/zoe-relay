use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(ForwardCompatibleEnum)]
pub enum NonIntegerDiscriminant {
    #[discriminant("not_a_number")]  // Must be u32!
    Variant1,
    Unknown { discriminant: u32, data: Vec<u8> },
}