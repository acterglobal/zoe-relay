use forward_compatible_enum::ForwardCompatibleEnum;

// Test invalid serde bounds syntax - should fail to compile
#[derive(ForwardCompatibleEnum)]
#[forward_compatible(serde_serialize = 123)]  // Invalid: not a string
pub enum InvalidBounds1<T> {
    #[discriminant(0)]
    Value(T),
    
    Unknown { discriminant: u32, data: Vec<u8> },
}

fn main() {}