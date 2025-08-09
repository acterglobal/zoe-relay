use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(ForwardCompatibleEnum)]
pub enum MissingDiscriminant {
    Variant1,  // Missing #[discriminant(N)]
    #[discriminant(1)]
    Variant2,
    Unknown { discriminant: u32, data: Vec<u8> },
}