use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(ForwardCompatibleEnum)]
#[forward_compatible(unknown_attribute = "value")]  // Unknown attribute!
pub enum UnknownAttribute {
    #[discriminant(1)]
    Variant1,
    Unknown { discriminant: u32, data: Vec<u8> },
}