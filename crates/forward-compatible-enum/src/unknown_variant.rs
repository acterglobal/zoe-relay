use proc_macro2::Span;
use syn::{Error, Ident, Result};

/// Helper for generating the unknown variant
#[derive(Debug)]
pub struct UnknownVariant {
    pub ident: Ident,
}

impl UnknownVariant {
    /// Create a new unknown variant, ensuring it doesn't conflict with existing variants
    pub fn new(name: &str, existing_variants: &[&Ident]) -> Result<Self> {
        // Validate the identifier name before creating it
        if !is_valid_rust_identifier(name) {
            return Err(Error::new(
                Span::call_site(),
                format!("'{name}' is not a valid identifier"),
            ));
        }

        let ident = Ident::new(name, Span::call_site());

        // Check for conflicts with existing variants
        for existing in existing_variants {
            if ident == **existing {
                return Err(Error::new_spanned(
                    existing,
                    format!("unknown variant name '{name}' conflicts with existing variant"),
                ));
            }
        }

        // Validate the identifier
        if !is_valid_rust_identifier(name) {
            return Err(Error::new(
                Span::call_site(),
                format!("'{name}' is not a valid Rust identifier"),
            ));
        }

        Ok(UnknownVariant { ident })
    }
}

fn is_valid_rust_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    let mut chars = s.chars();

    // First character must be a letter or underscore
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }

    // Remaining characters must be alphanumeric or underscore
    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return false;
        }
    }

    // Check if it's a Rust keyword
    !is_rust_keyword(s)
}

fn is_rust_keyword(s: &str) -> bool {
    matches!(
        s,
        "as" | "break"
            | "const"
            | "continue"
            | "crate"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "Self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
            | "try"
            | "macro"
            | "raw"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_unknown_variant() {
        let active_ident = Ident::new("Active", Span::call_site());
        let existing = vec![&active_ident];
        let result = UnknownVariant::new("Unknown", &existing);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().ident, "Unknown");
    }

    #[test]
    fn test_conflicting_unknown_variant() {
        let unknown_ident = Ident::new("Unknown", Span::call_site());
        let existing = vec![&unknown_ident];
        let result = UnknownVariant::new("Unknown", &existing);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_identifier() {
        let existing = vec![];
        assert!(UnknownVariant::new("123Invalid", &existing).is_err());
        assert!(UnknownVariant::new("", &existing).is_err());
        assert!(UnknownVariant::new("fn", &existing).is_err());
        assert!(UnknownVariant::new("let", &existing).is_err());
    }

    #[test]
    fn test_valid_identifiers() {
        let existing = vec![];
        assert!(UnknownVariant::new("Valid", &existing).is_ok());
        assert!(UnknownVariant::new("_valid", &existing).is_ok());
        assert!(UnknownVariant::new("valid_123", &existing).is_ok());
        assert!(UnknownVariant::new("UnknownVariant", &existing).is_ok());
    }
}
