use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::FileRef;

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

    /// Additional image-specific metadata
    pub metadata: BTreeMap<String, String>,
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
            metadata: BTreeMap::new(),
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

    /// Add metadata to the image
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
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
