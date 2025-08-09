//! Compile-time failure tests using trybuild
//!
//! These tests ensure that the macro properly validates input and provides
//! helpful error messages for common mistakes.

#[test]
fn ui_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
