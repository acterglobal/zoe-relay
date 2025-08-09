use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(ForwardCompatibleEnum)]  // Should fail - not an enum!
pub struct NotAnEnum {
    field: u32,
}