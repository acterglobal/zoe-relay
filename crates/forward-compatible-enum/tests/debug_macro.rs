use forward_compatible_enum::forward_compatible_enum;

#[forward_compatible_enum]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimpleEnum {
    #[discriminant(0)]
    A,

    #[discriminant(1)]
    B(String),
}

fn main() {
    // This will print the generated enum to see what's happening
    println!("SimpleEnum works: {:?}", SimpleEnum::A);
}
