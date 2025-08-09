use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(ForwardCompatibleEnum)]
#[forward_compatible(range = "10..20")]
pub enum OutOfRange {
    #[discriminant(5)]  // Outside range!
    Variant1,
    #[discriminant(15)]
    Variant2,
    Unknown { discriminant: u32, data: Vec<u8> },
}