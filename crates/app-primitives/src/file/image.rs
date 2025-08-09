use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{FileRef, Metadata};

/// Image reference with metadata
///
/// Contains a file reference to an image along with image-specific metadata
/// such as dimensions, format, and other properties useful for displaying images.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Image {
    /// Reference to the stored image file
    pub file_ref: FileRef,

    /// Image width in pixels (if known)
    pub width: Option<u32>,

    /// Image height in pixels (if known)
    pub height: Option<u32>,

    /// Alternative text for accessibility
    pub alt_text: Option<String>,

    /// Human-readable caption or description
    pub caption: Option<String>,

    /// Image format (e.g., "PNG", "JPEG", "WEBP")
    /// This may differ from content_type in the FileRef as it's more specific to images
    pub format: Option<String>,

    /// Additional image-specific metadata using structured types
    pub metadata: Vec<Metadata>,
}

impl Image {
    /// Create a new Image with just a file reference
    pub fn new(file_ref: FileRef) -> Self {
        Self {
            file_ref,
            width: None,
            height: None,
            alt_text: None,
            caption: None,
            format: None,
            metadata: vec![],
        }
    }

    /// Set image dimensions
    pub fn with_dimensions(mut self, width: u32, height: u32) -> Self {
        self.width = Some(width);
        self.height = Some(height);
        self
    }

    /// Set alternative text for accessibility
    pub fn with_alt_text(mut self, alt_text: String) -> Self {
        self.alt_text = Some(alt_text);
        self
    }

    /// Set image caption or description
    pub fn with_caption(mut self, caption: String) -> Self {
        self.caption = Some(caption);
        self
    }

    /// Set image format
    pub fn with_format(mut self, format: String) -> Self {
        self.format = Some(format);
        self
    }

    /// Add generic metadata to the image
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.push(Metadata::Generic(key, value));
        self
    }

    /// Add structured metadata to the image
    pub fn with_structured_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata.push(metadata);
        self
    }

    /// Get all generic metadata as a key-value map for backward compatibility
    ///
    /// This method extracts only the `Metadata::Generic(key, value)` entries and returns them
    /// as a `BTreeMap<String, String>` for backward compatibility with APIs that expect
    /// key-value metadata.
    pub fn generic_metadata(&self) -> BTreeMap<String, String> {
        self.metadata
            .iter()
            .filter_map(|meta| match meta {
                Metadata::Generic(key, value) => Some((key.clone(), value.clone())),
                _ => None,
            })
            .collect()
    }

    /// Get the aspect ratio (width/height) if dimensions are available
    pub fn aspect_ratio(&self) -> Option<f32> {
        match (self.width, self.height) {
            (Some(w), Some(h)) if h > 0 => Some(w as f32 / h as f32),
            _ => None,
        }
    }

    /// Check if this is a square image
    pub fn is_square(&self) -> Option<bool> {
        match (self.width, self.height) {
            (Some(w), Some(h)) => Some(w == h),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zoe_encrypted_storage::ConvergentEncryptionInfo;

    fn create_test_file_ref() -> FileRef {
        FileRef::new(
            "image_hash_123".to_string(),
            ConvergentEncryptionInfo {
                key: [1u8; 32],
                was_compressed: false,
                source_size: 2048,
            },
            Some("test_image.png".to_string()),
        )
        .with_content_type("image/png".to_string())
    }

    #[test]
    fn test_image_new() {
        let file_ref = create_test_file_ref();
        let image = Image::new(file_ref.clone());

        assert_eq!(image.file_ref, file_ref);
        assert_eq!(image.width, None);
        assert_eq!(image.height, None);
        assert_eq!(image.alt_text, None);
        assert_eq!(image.caption, None);
        assert_eq!(image.format, None);
        assert!(image.metadata.is_empty());
    }

    #[test]
    fn test_image_with_dimensions() {
        let image = Image::new(create_test_file_ref()).with_dimensions(1920, 1080);

        assert_eq!(image.width, Some(1920));
        assert_eq!(image.height, Some(1080));
    }

    #[test]
    fn test_image_with_alt_text() {
        let alt_text = "A beautiful sunset over the mountains".to_string();
        let image = Image::new(create_test_file_ref()).with_alt_text(alt_text.clone());

        assert_eq!(image.alt_text, Some(alt_text));
    }

    #[test]
    fn test_image_with_caption() {
        let caption = "Sunset at Mountain View, 2023".to_string();
        let image = Image::new(create_test_file_ref()).with_caption(caption.clone());

        assert_eq!(image.caption, Some(caption));
    }

    #[test]
    fn test_image_with_format() {
        let format = "PNG".to_string();
        let image = Image::new(create_test_file_ref()).with_format(format.clone());

        assert_eq!(image.format, Some(format));
    }

    #[test]
    fn test_image_with_metadata() {
        let image = Image::new(create_test_file_ref())
            .with_metadata("camera".to_string(), "Canon EOS R5".to_string())
            .with_metadata("iso".to_string(), "200".to_string())
            .with_metadata("aperture".to_string(), "f/8".to_string());

        let generic_meta = image.generic_metadata();
        assert_eq!(
            generic_meta.get("camera"),
            Some(&"Canon EOS R5".to_string())
        );
        assert_eq!(generic_meta.get("iso"), Some(&"200".to_string()));
        assert_eq!(generic_meta.get("aperture"), Some(&"f/8".to_string()));
        assert_eq!(image.metadata.len(), 3);
    }

    #[test]
    fn test_image_aspect_ratio() {
        // Test with standard 16:9 aspect ratio
        let image_16_9 = Image::new(create_test_file_ref()).with_dimensions(1920, 1080);
        assert_eq!(image_16_9.aspect_ratio(), Some(1920.0 / 1080.0));

        // Test with square image
        let image_square = Image::new(create_test_file_ref()).with_dimensions(500, 500);
        assert_eq!(image_square.aspect_ratio(), Some(1.0));

        // Test with portrait orientation
        let image_portrait = Image::new(create_test_file_ref()).with_dimensions(1080, 1920);
        assert_eq!(image_portrait.aspect_ratio(), Some(1080.0 / 1920.0));

        // Test with no dimensions
        let image_no_dims = Image::new(create_test_file_ref());
        assert_eq!(image_no_dims.aspect_ratio(), None);

        // Test with zero height (edge case)
        let mut image_zero_height = Image::new(create_test_file_ref());
        image_zero_height.width = Some(1920);
        image_zero_height.height = Some(0);
        assert_eq!(image_zero_height.aspect_ratio(), None);

        // Test with only width
        let mut image_only_width = Image::new(create_test_file_ref());
        image_only_width.width = Some(1920);
        assert_eq!(image_only_width.aspect_ratio(), None);

        // Test with only height
        let mut image_only_height = Image::new(create_test_file_ref());
        image_only_height.height = Some(1080);
        assert_eq!(image_only_height.aspect_ratio(), None);
    }

    #[test]
    fn test_image_is_square() {
        // Test square image
        let image_square = Image::new(create_test_file_ref()).with_dimensions(500, 500);
        assert_eq!(image_square.is_square(), Some(true));

        // Test non-square image
        let image_rectangle = Image::new(create_test_file_ref()).with_dimensions(1920, 1080);
        assert_eq!(image_rectangle.is_square(), Some(false));

        // Test with no dimensions
        let image_no_dims = Image::new(create_test_file_ref());
        assert_eq!(image_no_dims.is_square(), None);

        // Test with only width
        let mut image_only_width = Image::new(create_test_file_ref());
        image_only_width.width = Some(500);
        assert_eq!(image_only_width.is_square(), None);

        // Test with only height
        let mut image_only_height = Image::new(create_test_file_ref());
        image_only_height.height = Some(500);
        assert_eq!(image_only_height.is_square(), None);
    }

    #[test]
    fn test_image_builder_pattern() {
        let image = Image::new(create_test_file_ref())
            .with_dimensions(1920, 1080)
            .with_alt_text("Test image".to_string())
            .with_caption("A test image for unit tests".to_string())
            .with_format("PNG".to_string())
            .with_metadata("created_by".to_string(), "test_suite".to_string());

        assert_eq!(image.width, Some(1920));
        assert_eq!(image.height, Some(1080));
        assert_eq!(image.alt_text, Some("Test image".to_string()));
        assert_eq!(
            image.caption,
            Some("A test image for unit tests".to_string())
        );
        assert_eq!(image.format, Some("PNG".to_string()));
        let generic_meta = image.generic_metadata();
        assert_eq!(
            generic_meta.get("created_by"),
            Some(&"test_suite".to_string())
        );
    }

    #[test]
    fn test_postcard_serialization_image() {
        let image = Image::new(create_test_file_ref())
            .with_dimensions(800, 600)
            .with_alt_text("Serialization test".to_string())
            .with_caption("Testing postcard serialization".to_string())
            .with_format("JPEG".to_string())
            .with_metadata("test".to_string(), "serialization".to_string());

        let serialized = postcard::to_stdvec(&image).expect("Failed to serialize");
        let deserialized: Image = postcard::from_bytes(&serialized).expect("Failed to deserialize");

        assert_eq!(image, deserialized);
    }

    #[test]
    fn test_image_with_complex_metadata() {
        use crate::Metadata;

        let complex_metadata = vec![
            Metadata::Generic("exif_date".to_string(), "2023-12-01T15:30:00Z".to_string()),
            Metadata::Generic("location".to_string(), "37.7749,-122.4194".to_string()),
            Metadata::Generic("device".to_string(), "iPhone 15 Pro".to_string()),
        ];

        let mut image = Image::new(create_test_file_ref());
        image.metadata = complex_metadata;

        // Add more metadata using the builder
        let final_image = image
            .with_metadata("edited".to_string(), "true".to_string())
            .with_metadata("editor".to_string(), "Photoshop".to_string());

        // Check metadata using generic_metadata() helper
        let generic_meta = final_image.generic_metadata();

        // Check original metadata is preserved
        assert_eq!(
            generic_meta.get("exif_date"),
            Some(&"2023-12-01T15:30:00Z".to_string())
        );
        assert_eq!(
            generic_meta.get("location"),
            Some(&"37.7749,-122.4194".to_string())
        );
        assert_eq!(
            generic_meta.get("device"),
            Some(&"iPhone 15 Pro".to_string())
        );

        // Check new metadata is added
        assert_eq!(generic_meta.get("edited"), Some(&"true".to_string()));
        assert_eq!(generic_meta.get("editor"), Some(&"Photoshop".to_string()));

        assert_eq!(final_image.metadata.len(), 5);
    }

    #[test]
    fn test_image_edge_cases() {
        // Test with very large dimensions
        let large_image = Image::new(create_test_file_ref()).with_dimensions(u32::MAX, u32::MAX);

        assert_eq!(large_image.width, Some(u32::MAX));
        assert_eq!(large_image.height, Some(u32::MAX));
        assert_eq!(large_image.is_square(), Some(true));
        assert_eq!(large_image.aspect_ratio(), Some(1.0));

        // Test with 1x1 pixel image
        let tiny_image = Image::new(create_test_file_ref()).with_dimensions(1, 1);

        assert_eq!(tiny_image.is_square(), Some(true));
        assert_eq!(tiny_image.aspect_ratio(), Some(1.0));

        // Test with very wide image
        let wide_image = Image::new(create_test_file_ref()).with_dimensions(10000, 1);

        assert_eq!(wide_image.is_square(), Some(false));
        assert_eq!(wide_image.aspect_ratio(), Some(10000.0));

        // Test with very tall image
        let tall_image = Image::new(create_test_file_ref()).with_dimensions(1, 10000);

        assert_eq!(tall_image.is_square(), Some(false));
        assert_eq!(tall_image.aspect_ratio(), Some(0.0001));
    }

    #[test]
    fn test_image_empty_strings() {
        // Test with empty strings
        let image = Image::new(create_test_file_ref())
            .with_alt_text("".to_string())
            .with_caption("".to_string())
            .with_format("".to_string())
            .with_metadata("".to_string(), "".to_string());

        assert_eq!(image.alt_text, Some("".to_string()));
        assert_eq!(image.caption, Some("".to_string()));
        assert_eq!(image.format, Some("".to_string()));
        let generic_meta = image.generic_metadata();
        assert_eq!(generic_meta.get(""), Some(&"".to_string()));
    }
}
