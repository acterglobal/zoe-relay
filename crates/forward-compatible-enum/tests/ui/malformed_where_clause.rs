use forward_compatible_enum::ForwardCompatibleEnum;

// Test malformed where clause - should fail to compile
#[derive(ForwardCompatibleEnum)]
#[forward_compatible(serde_serialize = "T: InvalidTrait::")]  // Invalid where clause syntax
pub enum MalformedWhere<T> {
    #[discriminant(0)]
    Value(T),
    
    Unknown { discriminant: u32, data: Vec<u8> },
}

fn main() {}