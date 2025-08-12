//! # Forward Compatible Enum
//!
//! A derive macro for creating forward-compatible enums that can gracefully handle unknown variants
//! when deserializing with [`postcard`](https://docs.rs/postcard/). This is essential for evolving
//! data formats without breaking existing deployments.
//!
//! ## The Problem
//!
//! When using postcard to serialize enums, adding new variants breaks compatibility with older
//! clients. This happens because postcard's enum format only includes a discriminant followed
//! by the variant data, with no length information. When an old client encounters an unknown
//! discriminant, it doesn't know how many bytes to skip.
//!
//! ## The Solution
//!
//! This crate provides a `ForwardCompatibleEnum` derive macro that:
//!
//! 1. **Serializes** enums as `(discriminant: u32, data: Vec<u8>)` tuples
//! 2. **Preserves** unknown variants as raw bytes during deserialization
//! 3. **Allows** explicit discriminant assignment for stable wire formats
//! 4. **Supports** generic enums with custom serde trait bounds
//! 5. **Maintains** full round-trip compatibility
//!
//! **Important:** Your enum must include an `Unknown` variant with `discriminant: u32` and `data: Vec<u8>` fields.
//!
//! ## Quick Start
//!
//! ```rust
//! use forward_compatible_enum::ForwardCompatibleEnum;
//!
//! #[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
//! pub enum MessageType {
//!     #[discriminant(10)]
//!     Text(String),
//!     
//!     #[discriminant(20)]
//!     Image { url: String, caption: Option<String> },
//!     
//!     #[discriminant(30)]
//!     File { name: String, size: u64 },
//!     
//!     /// Required: Unknown variant for forward compatibility
//!     ///
//!     /// This variant stores unknown enum variants from newer versions.
//!     /// It must have exactly these two fields with these exact names and types.
//!     Unknown {
//!         discriminant: u32,
//!         data: Vec<u8>,
//!     },
//! }
//!
//! // Serialize and deserialize with postcard
//! let message = MessageType::Text("Hello, world!".to_string());
//! let bytes = postcard::to_stdvec(&message).unwrap();
//! let recovered: MessageType = postcard::from_bytes(&bytes).unwrap();
//! assert_eq!(message, recovered);
//! ```
//!
//! ## Generic Enums
//!
//! For enums with generic type parameters, specify custom serde bounds:
//!
//! ```rust
//! use forward_compatible_enum::ForwardCompatibleEnum;
//! use serde::{Serialize, de::DeserializeOwned};
//!
//! #[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
//! #[forward_compatible(
//!     serde_serialize = "T: Serialize",
//!     serde_deserialize = "T: DeserializeOwned"
//! )]
//! pub enum Event<T> {
//!     #[discriminant(1)]
//!     Data(T),
//!     
//!     #[discriminant(2)]
//!     Notification { content: T, id: u32 },
//!     
//!     /// Unknown variant for forward compatibility
//!     Unknown { discriminant: u32, data: Vec<u8> },
//! }
//!
//! // Works with any serializable type
//! let event = Event::Data("Hello".to_string());
//! let bytes = postcard::to_stdvec(&event).unwrap();
//! let recovered: Event<String> = postcard::from_bytes(&bytes).unwrap();
//! assert_eq!(event, recovered);
//! ```
//!
//! ## Wire Format
//!
//! The macro generates a wire format compatible with postcard:
//!
//! ```text
//! [discriminant: varint(u32)][data_length: varint(usize)][data_bytes: Vec<u8>]
//! ```
//!
//! Since `Vec<u8>` is already length-prefixed in postcard, this provides the necessary
//! information for old clients to skip unknown variants gracefully.
//!
//! ## Advanced Usage
//!
//! ### Custom Unknown Variant
//!
//! You can customize the name of the unknown variant:
//!
//! ```rust
//! use forward_compatible_enum::ForwardCompatibleEnum;
//!
//! #[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
//! #[forward_compatible(unknown_variant = "UnknownMessageType")]
//! pub enum MessageType {
//!     #[discriminant(10)]
//!     Text(String),
//!     
//!     #[discriminant(20)]
//!     Image { url: String },
//!     
//!     /// Custom name for the unknown variant
//!     UnknownMessageType {
//!         discriminant: u32,
//!         data: Vec<u8>,
//!     },
//! }
//! ```
//!
//! ### Discriminant Validation
//!
//! You can enforce that discriminants fall within a specific range:
//!
//! ```rust
//! use forward_compatible_enum::ForwardCompatibleEnum;
//!
//! #[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
//! #[forward_compatible(range = "100..200")]
//! pub enum MessageType {
//!     #[discriminant(100)]
//!     Text(String),
//!     
//!     #[discriminant(150)]
//!     Image { url: String },
//!     
//!     /// Unknown variants can have discriminants outside the range
//!     Unknown {
//!         discriminant: u32,
//!         data: Vec<u8>,
//!     },
//! }
//! ```
//!
//! ## Required Unknown Variant
//!
//! **Important:** Every enum using `ForwardCompatibleEnum` must include an Unknown variant.
//!
//! The Unknown variant:
//! - **Must** be a struct variant with exactly two fields: `discriminant: u32` and `data: Vec<u8>`
//! - **Must** use the exact field names `discriminant` and `data`
//! - **Can** have a custom name using `#[forward_compatible(unknown_variant = "CustomName")]`
//! - **Stores** data from newer enum variants that this version doesn't recognize
//! - **Enables** forward compatibility by preserving unknown data during round-trip serialization
//!
//! Without the Unknown variant, the macro will produce a compile error.
//!
//! ## Migration Strategy
//!
//! 1. **Deploy** the new format in your application
//! 2. **Handle** unknown variants appropriately (ignore, log, display as "unsupported")
//! 3. **Add** new enum variants safely without breaking older deployments
//!
//! ## Comparison with Standard Enums
//!
//! | Feature | Standard Enum | ForwardCompatibleEnum |
//! |---------|---------------|----------------------|
//! | Adding variants | ❌ Breaks old clients | ✅ Graceful degradation |
//! | Wire overhead | Minimal | Small overhead (+4-8 bytes) |
//! | Type safety | Full | Full for known variants |
//! | Round-trip fidelity | N/A | ✅ Preserves unknown data |
//!
//! ## Performance
//!
//! The macro adds minimal overhead:
//! - **Serialization**: Extra `Vec<u8>` allocation and discriminant encoding
//! - **Deserialization**: Unknown variants stored as raw bytes
//! - **Memory**: 4-8 bytes overhead per enum value
//!
//! For most applications, this overhead is negligible compared to the benefits of
//! forward compatibility.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![deny(unsafe_code)]

use proc_macro::TokenStream;

mod derive;
mod unknown_variant;

/// An attribute macro for creating forward-compatible enums.
///
/// This macro transforms a regular enum into one that can handle unknown variants
/// gracefully during deserialization, making it safe to add new variants without
/// breaking existing deployments.
///
/// # Basic Usage
///
/// ```rust
/// use forward_compatible_enum::ForwardCompatibleEnum;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
/// pub enum Status {
///     #[discriminant(0)]
///     Active,
///     
///     #[discriminant(1)]
///     Inactive,
///     
///     #[discriminant(2)]
///     Pending { reason: String },
///     
///     /// Unknown variant for forward compatibility
///     Unknown { discriminant: u32, data: Vec<u8> },
/// }
/// ```
///
/// # Attributes
///
/// ## `#[discriminant(N)]`
///
/// Assigns an explicit discriminant value to a variant. This is required for all
/// variants to ensure stable wire format.
///
/// ```rust
/// # use forward_compatible_enum::ForwardCompatibleEnum;
/// #[derive(ForwardCompatibleEnum)]
/// pub enum Priority {
///     #[discriminant(10)]
///     Low,
///     
///     #[discriminant(50)]
///     High,
///     
///     // Gaps are allowed - useful for future additions
///     #[discriminant(100)]
///     Critical,
///     
///     /// Unknown variant for forward compatibility
///     Unknown { discriminant: u32, data: Vec<u8> },
/// }
/// ```
///
/// ## `#[forward_compatible(...)]`
///
/// Container attribute for configuring the macro behavior:
///
/// - `unknown_variant = "Name"`: Customizes the name of the generated unknown variant
/// - `range = "min..max"`: Validates that all discriminants fall within the specified range
/// - `serde_serialize = "bounds"`: Custom trait bounds for the `Serialize` implementation
/// - `serde_deserialize = "bounds"`: Custom trait bounds for the `Deserialize` implementation
///
/// ```rust
/// # use forward_compatible_enum::ForwardCompatibleEnum;
/// #[derive(ForwardCompatibleEnum)]
/// #[forward_compatible(
///     unknown_variant = "UnknownPriority",
///     range = "0..1000"
/// )]
/// pub enum Priority {
///     #[discriminant(0)]
///     Low,
///     
///     #[discriminant(999)]
///     Extreme,
///     
///     /// Unknown variant for forward compatibility
///     UnknownPriority { discriminant: u32, data: Vec<u8> },
/// }
/// ```
///
/// ## Generic Type Support with Custom Serde Bounds
///
/// For enums with generic type parameters, you may need to specify custom trait bounds
/// for the `Serialize` and `Deserialize` implementations. Use the `serde_serialize` and
/// `serde_deserialize` attributes to provide these bounds:
///
/// ```rust
/// # use forward_compatible_enum::ForwardCompatibleEnum;
/// # use serde::{Serialize, de::DeserializeOwned};
/// #[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
/// #[forward_compatible(
///     serde_serialize = "T: Serialize",
///     serde_deserialize = "T: DeserializeOwned"
/// )]
/// pub enum Message<T> {
///     #[discriminant(1)]
///     Data(T),
///     
///     #[discriminant(2)]
///     Notification { content: T, priority: u8 },
///     
///     #[discriminant(3)]
///     Bulk(Vec<T>),
///     
///     /// Unknown variant for forward compatibility
///     Unknown { discriminant: u32, data: Vec<u8> },
/// }
/// ```
///
/// ### Multiple Generic Parameters
///
/// For enums with multiple generic parameters, specify bounds for all parameters:
///
/// ```rust
/// # use forward_compatible_enum::ForwardCompatibleEnum;
/// # use serde::{Serialize, de::DeserializeOwned};
/// #[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
/// #[forward_compatible(
///     serde_serialize = "T: Serialize, U: Serialize",
///     serde_deserialize = "T: DeserializeOwned, U: DeserializeOwned"
/// )]
/// pub enum Envelope<T, U> {
///     #[discriminant(10)]
///     Primary(T),
///     
///     #[discriminant(20)]
///     Secondary(U),
///     
///     #[discriminant(30)]
///     Combined { first: T, second: U },
///     
///     /// Unknown variant for forward compatibility
///     Unknown { discriminant: u32, data: Vec<u8> },
/// }
/// ```
///
/// ### Complex Trait Bounds
///
/// You can specify complex trait bounds including multiple traits and where clauses:
///
/// ```rust
/// # use forward_compatible_enum::ForwardCompatibleEnum;
/// # use serde::{Serialize, de::DeserializeOwned};
/// #[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
/// #[forward_compatible(
///     serde_serialize = "T: Serialize + Clone + Send",
///     serde_deserialize = "T: DeserializeOwned + Clone + Send"
/// )]
/// pub enum Event<T> {
///     #[discriminant(1)]
///     Activity(T),
///     
///     /// Unknown variant for forward compatibility
///     Unknown { discriminant: u32, data: Vec<u8> },
/// }
/// ```
///
/// ### Backward Compatibility
///
/// The serde bounds feature is fully backward compatible. Enums without generic parameters
/// or custom bounds work exactly as before:
///
/// ```rust
/// # use forward_compatible_enum::ForwardCompatibleEnum;
/// // This works without any serde bounds - fully backward compatible
/// #[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
/// pub enum Status {
///     #[discriminant(0)]
///     Active,
///     
///     #[discriminant(1)]
///     Inactive,
///     
///     /// Unknown variant for forward compatibility
///     Unknown { discriminant: u32, data: Vec<u8> },
/// }
/// ```
///
/// ### Notes on Serde Bounds
///
/// - **Optional**: Only needed for generic enums where the default trait bounds are insufficient
/// - **Syntax**: Use standard Rust where-clause syntax (e.g., `"T: Serialize + Clone"`)
/// - **Separate**: Specify serialize and deserialize bounds independently if needed
/// - **Multiple Parameters**: Comma-separate bounds for multiple type parameters
/// - **Standard Traits**: Most commonly used with `Serialize` and `DeserializeOwned`
///
/// # Generated Code
///
/// The macro generates:
///
/// 1. An additional `Unknown { discriminant: u32, data: Vec<u8> }` variant
/// 2. Custom `Serialize` implementation using `(discriminant, Vec<u8>)` format
/// 3. Custom `Deserialize` implementation that preserves unknown variants
/// 4. All original derives are preserved on the transformed enum
///
/// # Wire Format
///
/// Data is serialized as a tuple: `(discriminant: u32, data: Vec<u8>)`
///
/// This format is compatible with postcard and provides the length information
/// needed for old clients to skip unknown variants.
///
/// # Error Handling
///
/// The macro performs compile-time validation:
///
/// - All variants must have explicit `#[discriminant(N)]` attributes
/// - Discriminant values must be unique
/// - Discriminants must fall within the specified range (if provided)
/// - The unknown variant name must not conflict with existing variants
///
/// Compilation will fail with clear error messages if any validation fails.
#[proc_macro_attribute]
pub fn forward_compatible_enum(args: TokenStream, input: TokenStream) -> TokenStream {
    derive::expand_attribute(args, input)
}

/// A derive macro for creating enums with custom u32 discriminants.
///
/// This macro is designed for unit-variant enums (no associated data) that need
/// stable, custom discriminant values for serialization. It generates `From<u32>`
/// and `Into<u32>` implementations along with serde integration.
///
/// # Basic Usage
///
/// ```rust
/// use forward_compatible_enum::U32Discriminants;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
/// #[serde(from = "u32", into = "u32")]
/// pub enum Priority {
///     #[discriminant(0)]
///     Low,
///     
///     #[discriminant(5)]
///     Medium,
///     
///     #[discriminant(10)]
///     High,
/// }
/// ```
///
/// # Attributes
///
/// ## `#[discriminant(N)]`
///
/// Assigns a specific u32 discriminant value to a variant. All variants must
/// have explicit discriminant assignments.
///
/// ## `#[u32_discriminants(fallback = "VariantName")]`
///
/// Specifies which variant should be used as the fallback when deserializing
/// unknown discriminant values. If not specified, the first variant is used.
///
/// ```rust
/// # use forward_compatible_enum::U32Discriminants;
/// #[derive(U32Discriminants)]
/// #[u32_discriminants(fallback = "Unknown")]
/// pub enum Status {
///     #[discriminant(1)]
///     Active,
///     
///     #[discriminant(2)]
///     Inactive,
///     
///     #[discriminant(0)]
///     Unknown, // Used as fallback for unknown discriminants
/// }
/// ```
///
/// # Generated Code
///
/// The macro generates:
///
/// 1. `From<u32>` implementation for deserialization
/// 2. `Into<u32>` implementation for serialization  
/// 3. `From<&EnumType>` for `u32` for reference conversion
///
/// You must manually add `#[serde(from = "u32", into = "u32")]` to enable serde integration.
///
/// # Wire Format
///
/// Values are serialized as plain u32 values using postcard's varint encoding,
/// making them very space-efficient for small discriminant values.
///
/// # Error Handling
///
/// Unknown discriminant values during deserialization are mapped to the fallback
/// variant (first variant by default), ensuring forward compatibility.
/// A derive macro for creating forward-compatible enums.
///
/// This macro provides a convenient derive syntax for creating forward-compatible enums.
/// It generates custom `Serialize` and `Deserialize` implementations that handle unknown variants.
///
/// **Important:** Your enum must include an `Unknown` variant with `discriminant: u32` and `data: Vec<u8>` fields.
///
/// # Example
///
/// ```rust
/// use forward_compatible_enum::ForwardCompatibleEnum;
///
/// #[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
/// pub enum Message {
///     #[discriminant(1)]
///     Text(String),
///     
///     #[discriminant(2)]
///     Image { url: String },
///     
///     // Required: Unknown variant for forward compatibility
///     Unknown {
///         discriminant: u32,
///         data: Vec<u8>,
///     },
/// }
/// ```
///
/// See the crate-level documentation for detailed usage information.
#[proc_macro_derive(ForwardCompatibleEnum, attributes(discriminant, forward_compatible))]
pub fn derive_forward_compatible_enum(input: TokenStream) -> TokenStream {
    derive::expand_derive(input)
}

/// A derive macro for creating enums with custom u32 discriminants.
///
/// This macro is designed for unit-variant enums (no associated data) that need
/// stable, custom discriminant values for serialization. It generates `From<u32>`
/// and `Into<u32>` implementations along with serde integration.
///
/// See the documentation for `U32Discriminants` for detailed usage information.
#[proc_macro_derive(U32Discriminants, attributes(discriminant, u32_discriminants))]
pub fn derive_u32_discriminants(input: TokenStream) -> TokenStream {
    derive::expand_u32_discriminants(input)
}
