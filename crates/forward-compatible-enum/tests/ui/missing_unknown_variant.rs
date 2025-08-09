use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(ForwardCompatibleEnum)]
pub enum MissingUnknownVariant {
    #[discriminant(1)]
    Variant1,
    #[discriminant(2)]
    Variant2,
    // Missing Unknown variant!
}