use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{ToTokens, quote};
use syn::{
    Attribute, Data, DeriveInput, Error, Fields, Ident, Lit, Result, Variant, Visibility,
    parse_macro_input,
};

use crate::unknown_variant::UnknownVariant;

/// Configuration for the forward compatible enum macro
#[derive(Debug, Default)]
struct ForwardCompatibleConfig {
    /// Name for the unknown variant (default: "Unknown")
    unknown_variant: Option<String>,
    /// Range validation for discriminants (e.g., "0..100")
    range: Option<(u32, u32)>,
}

/// Information about a single enum variant
#[derive(Debug)]
struct VariantInfo {
    /// The original variant
    variant: Variant,
    /// The explicit discriminant value
    discriminant: u32,
}

/// Main entry point for the attribute macro
pub fn expand_attribute(args: TokenStream, input: TokenStream) -> TokenStream {
    let _args = args; // Parse args if needed in the future
    let input = parse_macro_input!(input as DeriveInput);

    match expand_attribute_impl(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Main entry point for the ForwardCompatibleEnum derive macro
pub fn expand_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match expand_derive_impl(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Main entry point for the U32Discriminants derive macro
pub fn expand_u32_discriminants(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match expand_u32_discriminants_impl(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn expand_attribute_impl(input: DeriveInput) -> Result<TokenStream2> {
    // Parse and validate the input
    let config = parse_container_attributes(&input.attrs)?;
    let variants = parse_enum_variants(&input)?;

    // Validate discriminants
    validate_discriminants(&variants, &config)?;

    // Generate the transformed enum and implementations
    let enum_name = &input.ident;
    let vis = &input.vis;
    let generics = &input.generics;

    // Create unknown variant
    let unknown_variant = UnknownVariant::new(
        config.unknown_variant.as_deref().unwrap_or("Unknown"),
        &variants
            .iter()
            .map(|v| &v.variant.ident)
            .collect::<Vec<_>>(),
    )?;

    // Generate the new enum with unknown variant
    let new_enum = generate_enum(
        enum_name,
        vis,
        generics,
        &variants,
        &unknown_variant,
        &input.attrs,
    )?;

    // Generate serialize implementation
    let serialize_impl = generate_serialize_impl(enum_name, generics, &variants, &unknown_variant)?;

    // Generate deserialize implementation
    let deserialize_impl =
        generate_deserialize_impl(enum_name, generics, &variants, &unknown_variant)?;

    Ok(quote! {
        #new_enum
        #serialize_impl
        #deserialize_impl
    })
}

fn expand_derive_impl(input: DeriveInput) -> Result<TokenStream2> {
    // Parse and validate the input
    let config = parse_container_attributes(&input.attrs)?;
    let (known_variants, _unknown_variant_info) = parse_enum_variants_for_derive(&input, &config)?;

    // Validate discriminants for known variants only
    validate_discriminants(&known_variants, &config)?;

    // Generate implementations
    let enum_name = &input.ident;
    let generics = &input.generics;

    // Create unknown variant descriptor
    let unknown_variant_name = config.unknown_variant.as_deref().unwrap_or("Unknown");
    let unknown_variant = UnknownVariant::new(
        unknown_variant_name,
        &known_variants
            .iter()
            .map(|v| &v.variant.ident)
            .collect::<Vec<_>>(),
    )?;

    // Generate serialize implementation
    let serialize_impl =
        generate_serialize_impl(enum_name, generics, &known_variants, &unknown_variant)?;

    // Generate deserialize implementation
    let deserialize_impl =
        generate_deserialize_impl(enum_name, generics, &known_variants, &unknown_variant)?;

    Ok(quote! {
        #serialize_impl
        #deserialize_impl
    })
}

fn parse_enum_variants_for_derive(
    input: &DeriveInput,
    config: &ForwardCompatibleConfig,
) -> Result<(Vec<VariantInfo>, syn::Variant)> {
    let data = match &input.data {
        Data::Enum(data) => data,
        _ => {
            return Err(Error::new_spanned(
                input,
                "ForwardCompatibleEnum can only be applied to enums",
            ));
        }
    };

    // Find and validate the unknown variant
    let unknown_variant_name = config.unknown_variant.as_deref().unwrap_or("Unknown");
    let unknown_variant_ident = match syn::parse_str::<Ident>(unknown_variant_name) {
        Ok(ident) => ident,
        Err(_) => {
            return Err(Error::new_spanned(
                input,
                format!("'{unknown_variant_name}' is not a valid identifier"),
            ));
        }
    };

    // Split variants into known variants (with discriminants) and unknown variant
    let mut known_variants = Vec::new();
    let mut unknown_variant_info = None;

    for variant in &data.variants {
        if variant.ident == unknown_variant_ident {
            // Validate that the unknown variant has the correct structure
            match &variant.fields {
                Fields::Named(fields) => {
                    let field_names: Vec<_> = fields
                        .named
                        .iter()
                        .map(|f| f.ident.as_ref().unwrap().to_string())
                        .collect();
                    if field_names.len() != 2
                        || !field_names.contains(&"discriminant".to_string())
                        || !field_names.contains(&"data".to_string())
                    {
                        return Err(Error::new_spanned(
                            variant,
                            format!(
                                "Unknown variant '{unknown_variant_name}' must have exactly two fields: 'discriminant: u32' and 'data: Vec<u8>'"
                            ),
                        ));
                    }
                }
                _ => {
                    return Err(Error::new_spanned(
                        variant,
                        format!(
                            "Unknown variant '{unknown_variant_name}' must be a struct variant with 'discriminant: u32' and 'data: Vec<u8>' fields"
                        ),
                    ));
                }
            }
            unknown_variant_info = Some(variant.clone());
        } else {
            // Parse discriminant for known variants only
            let discriminant = parse_discriminant_attribute(&variant.attrs)?;
            known_variants.push(VariantInfo {
                variant: variant.clone(),
                discriminant,
            });
        }
    }

    let unknown_variant_info = unknown_variant_info.ok_or_else(|| {
        Error::new_spanned(
            input,
            format!("Enum must contain an Unknown variant named '{unknown_variant_name}'"),
        )
    })?;

    if known_variants.is_empty() {
        return Err(Error::new_spanned(
            input,
            "enum must have at least one non-Unknown variant",
        ));
    }

    Ok((known_variants, unknown_variant_info))
}

fn parse_container_attributes(attrs: &[Attribute]) -> Result<ForwardCompatibleConfig> {
    let mut config = ForwardCompatibleConfig::default();

    for attr in attrs {
        if attr.path().is_ident("forward_compatible") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("unknown_variant") {
                    let value: Lit = meta.value()?.parse()?;
                    if let Lit::Str(s) = value {
                        config.unknown_variant = Some(s.value());
                    } else {
                        return Err(meta.error("unknown_variant must be a string literal"));
                    }
                } else if meta.path.is_ident("range") {
                    let value: Lit = meta.value()?.parse()?;
                    if let Lit::Str(s) = value {
                        config.range = Some(parse_range(&s.value())?);
                    } else {
                        return Err(meta.error("range must be a string literal"));
                    }
                } else {
                    return Err(meta.error(format!(
                        "unknown attribute: {}",
                        meta.path.to_token_stream()
                    )));
                }
                Ok(())
            })?;
        }
    }

    Ok(config)
}

fn parse_range(range_str: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = range_str.split("..").collect();
    if parts.len() != 2 {
        return Err(Error::new(
            Span::call_site(),
            "range must be in format 'min..max'",
        ));
    }

    let min: u32 = parts[0]
        .parse()
        .map_err(|_| Error::new(Span::call_site(), "invalid minimum value in range"))?;

    let max: u32 = parts[1]
        .parse()
        .map_err(|_| Error::new(Span::call_site(), "invalid maximum value in range"))?;

    if min >= max {
        return Err(Error::new(
            Span::call_site(),
            "range minimum must be less than maximum",
        ));
    }

    Ok((min, max))
}

fn parse_enum_variants(input: &DeriveInput) -> Result<Vec<VariantInfo>> {
    let data = match &input.data {
        Data::Enum(data) => data,
        _ => {
            return Err(Error::new_spanned(
                input,
                "ForwardCompatibleEnum can only be applied to enums",
            ));
        }
    };

    let mut variants = Vec::new();

    for variant in &data.variants {
        let discriminant = parse_discriminant_attribute(&variant.attrs)?;
        variants.push(VariantInfo {
            variant: variant.clone(),
            discriminant,
        });
    }

    if variants.is_empty() {
        return Err(Error::new_spanned(
            input,
            "enum must have at least one variant",
        ));
    }

    Ok(variants)
}

fn parse_discriminant_attribute(attrs: &[Attribute]) -> Result<u32> {
    for attr in attrs {
        if attr.path().is_ident("discriminant") {
            return attr.parse_args::<syn::LitInt>()?.base10_parse::<u32>();
        }
    }

    Err(Error::new(
        Span::call_site(),
        "all variants must have #[discriminant(N)] attribute",
    ))
}

fn validate_discriminants(
    variants: &[VariantInfo],
    config: &ForwardCompatibleConfig,
) -> Result<()> {
    // Check for duplicate discriminants
    let mut seen = std::collections::HashSet::new();
    for variant in variants {
        if !seen.insert(variant.discriminant) {
            return Err(Error::new_spanned(
                &variant.variant,
                format!("duplicate discriminant value: {}", variant.discriminant),
            ));
        }
    }

    // Check range validation if specified
    if let Some((min, max)) = config.range {
        for variant in variants {
            if variant.discriminant < min || variant.discriminant >= max {
                return Err(Error::new_spanned(
                    &variant.variant,
                    format!(
                        "discriminant {} is outside allowed range {}..{}",
                        variant.discriminant, min, max
                    ),
                ));
            }
        }
    }

    Ok(())
}

fn generate_enum(
    name: &Ident,
    vis: &Visibility,
    generics: &syn::Generics,
    variants: &[VariantInfo],
    unknown_variant: &UnknownVariant,
    original_attrs: &[Attribute],
) -> Result<TokenStream2> {
    // For attribute macro, we keep all original derives and attributes
    let variant_tokens: Vec<_> = variants
        .iter()
        .map(|v| {
            let variant = &v.variant;
            // Remove the discriminant attribute from the variant
            let filtered_variant_attrs: Vec<_> = variant
                .attrs
                .iter()
                .filter(|attr| !attr.path().is_ident("discriminant"))
                .collect();

            let ident = &variant.ident;
            let fields = &variant.fields;

            quote! {
                #(#filtered_variant_attrs)*
                #ident #fields
            }
        })
        .collect();

    let unknown_ident = &unknown_variant.ident;

    Ok(quote! {
        #(#original_attrs)*
        #vis enum #name #generics {
            #(#variant_tokens,)*

            /// Unknown variant for forward compatibility.
            ///
            /// This variant stores the discriminant and raw data of enum variants
            /// that are not recognized by this version of the code. This allows
            /// older clients to gracefully handle data from newer versions.
            #unknown_ident {
                /// The discriminant value of the unknown variant
                discriminant: u32,
                /// The raw serialized data of the unknown variant
                data: ::std::vec::Vec<u8>,
            },
        }
    })
}

fn generate_serialize_impl(
    name: &Ident,
    generics: &syn::Generics,
    variants: &[VariantInfo],
    unknown_variant: &UnknownVariant,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let match_arms: Vec<_> = variants
        .iter()
        .map(|variant_info| {
            let variant_ident = &variant_info.variant.ident;
            let discriminant = variant_info.discriminant;

            match &variant_info.variant.fields {
                Fields::Unit => {
                    quote! {
                        #name::#variant_ident => {
                            let data = ::postcard::to_stdvec(&())
                                .map_err(|e| <S::Error as ::serde::ser::Error>::custom(
                                    ::std::format!("Failed to serialize unit variant: {}", e)
                                ))?;
                            (#discriminant, data)
                        }
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_names: Vec<_> = (0..fields.unnamed.len())
                        .map(|i| Ident::new(&format!("field_{i}"), Span::call_site()))
                        .collect();

                    let field_pattern = if field_names.len() == 1 {
                        quote! { #(#field_names),* }
                    } else {
                        quote! { ( #(#field_names),* ) }
                    };

                    quote! {
                        #name::#variant_ident(#field_pattern) => {
                            let data = ::postcard::to_stdvec(&(#(#field_names),*))
                                .map_err(|e| <S::Error as ::serde::ser::Error>::custom(
                                    ::std::format!("Failed to serialize tuple variant: {}", e)
                                ))?;
                            (#discriminant, data)
                        }
                    }
                }
                Fields::Named(fields) => {
                    let field_names: Vec<_> = fields
                        .named
                        .iter()
                        .map(|field| field.ident.as_ref().unwrap())
                        .collect();

                    quote! {
                        #name::#variant_ident { #(#field_names),* } => {
                            let data = ::postcard::to_stdvec(&(#(#field_names),*))
                                .map_err(|e| <S::Error as ::serde::ser::Error>::custom(
                                    ::std::format!("Failed to serialize struct variant: {}", e)
                                ))?;
                            (#discriminant, data)
                        }
                    }
                }
            }
        })
        .collect();

    let unknown_ident = &unknown_variant.ident;

    Ok(quote! {
        impl #impl_generics ::serde::Serialize for #name #ty_generics #where_clause {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                let (discriminant, data) = match self {
                    #(#match_arms)*
                    #name::#unknown_ident { discriminant, data } => (*discriminant, data.clone()),
                };

                (discriminant, data).serialize(serializer)
            }
        }
    })
}

fn generate_deserialize_impl(
    name: &Ident,
    generics: &syn::Generics,
    variants: &[VariantInfo],
    unknown_variant: &UnknownVariant,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let match_arms: Vec<_> = variants
        .iter()
        .map(|variant_info| {
            let variant_ident = &variant_info.variant.ident;
            let discriminant = variant_info.discriminant;

            match &variant_info.variant.fields {
                Fields::Unit => {
                    quote! {
                        #discriminant => {
                            let _: () = ::postcard::from_bytes(&data)
                                .map_err(|e| <D::Error as ::serde::de::Error>::custom(
                                    ::std::format!("Failed to deserialize unit variant: {}", e)
                                ))?;
                            ::std::result::Result::Ok(#name::#variant_ident)
                        }
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_types: Vec<_> = fields.unnamed
                        .iter()
                        .map(|field| &field.ty)
                        .collect();

                    if field_types.len() == 1 {
                        let field_type = &field_types[0];
                        quote! {
                            #discriminant => {
                                let field_0: #field_type = ::postcard::from_bytes(&data)
                                    .map_err(|e| <D::Error as ::serde::de::Error>::custom(
                                        ::std::format!("Failed to deserialize tuple variant: {}", e)
                                    ))?;
                                ::std::result::Result::Ok(#name::#variant_ident(field_0))
                            }
                        }
                    } else {
                        let field_indexes: Vec<_> = (0..field_types.len())
                            .map(syn::Index::from)
                            .collect();

                        quote! {
                            #discriminant => {
                                let fields: (#(#field_types),*) = ::postcard::from_bytes(&data)
                                    .map_err(|e| <D::Error as ::serde::de::Error>::custom(
                                        ::std::format!("Failed to deserialize tuple variant: {}", e)
                                    ))?;
                                ::std::result::Result::Ok(#name::#variant_ident(#(fields.#field_indexes),*))
                            }
                        }
                    }
                }
                Fields::Named(fields) => {
                    let field_names: Vec<_> = fields.named
                        .iter()
                        .map(|field| field.ident.as_ref().unwrap())
                        .collect();
                    let field_types: Vec<_> = fields.named
                        .iter()
                        .map(|field| &field.ty)
                        .collect();

                    quote! {
                        #discriminant => {
                            let (#(#field_names),*): (#(#field_types),*) = ::postcard::from_bytes(&data)
                                .map_err(|e| <D::Error as ::serde::de::Error>::custom(
                                    ::std::format!("Failed to deserialize struct variant: {}", e)
                                ))?;
                            ::std::result::Result::Ok(#name::#variant_ident { #(#field_names),* })
                        }
                    }
                }
            }
        })
        .collect();

    let unknown_ident = &unknown_variant.ident;

    Ok(quote! {
        impl<'de> #impl_generics ::serde::Deserialize<'de> for #name #ty_generics #where_clause {
            fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let (discriminant, data): (u32, ::std::vec::Vec<u8>) =
                    ::serde::Deserialize::deserialize(deserializer)?;

                match discriminant {
                    #(#match_arms)*
                    unknown_discriminant => {
                        ::std::result::Result::Ok(#name::#unknown_ident {
                            discriminant: unknown_discriminant,
                            data,
                        })
                    }
                }
            }
        }
    })
}

/// Configuration for the U32Discriminants enum macro
#[derive(Debug, Default)]
struct U32DiscriminantsConfig {
    /// Name of the variant to use as fallback for unknown discriminants
    fallback_variant: Option<String>,
}

fn expand_u32_discriminants_impl(input: DeriveInput) -> Result<TokenStream2> {
    // Parse and validate the input
    let config = parse_u32_discriminants_attributes(&input.attrs)?;
    let variants = parse_enum_variants(&input)?;

    // Validate that all variants are unit variants
    validate_unit_variants(&variants)?;

    // Validate discriminants
    validate_discriminants(&variants, &ForwardCompatibleConfig::default())?;

    // Generate implementations
    let enum_name = &input.ident;
    let generics = &input.generics;

    // Generate From<u32> implementation
    let from_u32_impl = generate_from_u32_impl(enum_name, generics, &variants, &config)?;

    // Generate Into<u32> implementation
    let into_u32_impl = generate_into_u32_impl(enum_name, generics, &variants)?;

    // For derive macros, we can't add attributes to the original type
    // The user needs to add #[serde(from = "u32", into = "u32")] manually
    Ok(quote! {
        #from_u32_impl
        #into_u32_impl
    })
}

fn parse_u32_discriminants_attributes(attrs: &[Attribute]) -> Result<U32DiscriminantsConfig> {
    let mut config = U32DiscriminantsConfig::default();

    for attr in attrs {
        if attr.path().is_ident("u32_discriminants") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("fallback") {
                    let value: Lit = meta.value()?.parse()?;
                    if let Lit::Str(s) = value {
                        config.fallback_variant = Some(s.value());
                    } else {
                        return Err(meta.error("fallback must be a string literal"));
                    }
                } else {
                    return Err(meta.error(format!(
                        "unknown attribute: {}",
                        meta.path.to_token_stream()
                    )));
                }
                Ok(())
            })?;
        }
    }

    Ok(config)
}

fn validate_unit_variants(variants: &[VariantInfo]) -> Result<()> {
    for variant in variants {
        match &variant.variant.fields {
            Fields::Unit => {}
            _ => {
                return Err(Error::new_spanned(
                    &variant.variant,
                    "U32Discriminants only supports unit variants (no associated data)",
                ));
            }
        }
    }
    Ok(())
}

fn generate_from_u32_impl(
    name: &Ident,
    generics: &syn::Generics,
    variants: &[VariantInfo],
    config: &U32DiscriminantsConfig,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Determine fallback variant
    let fallback_variant = if let Some(fallback_name) = &config.fallback_variant {
        // Find the specified fallback variant
        variants
            .iter()
            .find(|v| v.variant.ident == fallback_name)
            .ok_or_else(|| {
                Error::new(
                    Span::call_site(),
                    format!("fallback variant '{fallback_name}' not found"),
                )
            })?
    } else {
        // Use the first variant as fallback
        variants
            .first()
            .ok_or_else(|| Error::new(Span::call_site(), "enum must have at least one variant"))?
    };

    let match_arms: Vec<_> = variants
        .iter()
        .map(|variant_info| {
            let variant_ident = &variant_info.variant.ident;
            let discriminant = variant_info.discriminant;

            quote! {
                #discriminant => #name::#variant_ident,
            }
        })
        .collect();

    let fallback_ident = &fallback_variant.variant.ident;

    Ok(quote! {
        impl #impl_generics ::std::convert::From<u32> for #name #ty_generics #where_clause {
            fn from(value: u32) -> Self {
                match value {
                    #(#match_arms)*
                    _ => #name::#fallback_ident, // Fallback for unknown discriminants
                }
            }
        }
    })
}

fn generate_into_u32_impl(
    name: &Ident,
    generics: &syn::Generics,
    variants: &[VariantInfo],
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let match_arms: Vec<_> = variants
        .iter()
        .map(|variant_info| {
            let variant_ident = &variant_info.variant.ident;
            let discriminant = variant_info.discriminant;

            quote! {
                #name::#variant_ident => #discriminant,
            }
        })
        .collect();

    Ok(quote! {
        impl #impl_generics ::std::convert::Into<u32> for #name #ty_generics #where_clause {
            fn into(self) -> u32 {
                match self {
                    #(#match_arms)*
                }
            }
        }

        impl #impl_generics ::std::convert::From<&#name #ty_generics> for u32 #where_clause {
            fn from(value: &#name #ty_generics) -> u32 {
                match value {
                    #(#match_arms)*
                }
            }
        }
    })
}
