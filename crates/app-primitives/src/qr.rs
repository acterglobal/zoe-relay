use qrcode::QrCode;
use qrcode::render::unicode;
use serde::Serialize;

/// Error types for QR code operations
#[derive(Debug, thiserror::Error)]
pub enum QrError {
    #[error("Serialization failed: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("QR code generation failed: {0}")]
    QrGeneration(#[from] qrcode::types::QrError),
}

/// Result type for QR code operations
pub type QrResult<T> = Result<T, QrError>;

/// QR code generation options
#[derive(Debug, Clone)]
pub struct QrOptions {
    /// Title to display above the QR code
    pub title: String,

    /// Subtitle lines to display below the title
    pub subtitle_lines: Vec<String>,

    /// Footer message to display below the QR code
    pub footer: String,

    /// Width of the display border (in characters)
    pub border_width: usize,
}

impl Default for QrOptions {
    fn default() -> Self {
        Self {
            title: "QR CODE".to_string(),
            subtitle_lines: Vec::new(),
            footer: "Scan to connect".to_string(),
            border_width: 60,
        }
    }
}

impl QrOptions {
    /// Create new QR options with a title
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            ..Default::default()
        }
    }

    /// Add a subtitle line
    pub fn with_subtitle(mut self, subtitle: impl Into<String>) -> Self {
        self.subtitle_lines.push(subtitle.into());
        self
    }

    /// Set the footer message
    pub fn with_footer(mut self, footer: impl Into<String>) -> Self {
        self.footer = footer.into();
        self
    }

    /// Set the border width
    pub fn with_border_width(mut self, width: usize) -> Self {
        self.border_width = width;
        self
    }
}

/// Generate binary data from any postcard-serializable data for QR code encoding
///
/// This function serializes the data using postcard and returns the binary data
/// directly for QR code generation.
///
/// # Arguments
/// * `data` - The data to encode (must implement Serialize)
///
/// # Returns
/// * `QrResult<Vec<u8>>` - The binary data that can be used to generate the QR code
///
/// # Examples
/// ```
/// use zoe_app_primitives::qr::generate_qr_data;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct MyData {
///     message: String,
/// }
///
/// let data = MyData { message: "Hello, World!".to_string() };
/// let qr_data = generate_qr_data(&data).unwrap();
/// ```
pub fn generate_qr_data<T: Serialize>(data: &T) -> QrResult<Vec<u8>> {
    // Serialize the data using postcard - return binary data directly
    let serialized = postcard::to_stdvec(data)?;
    Ok(serialized)
}

/// Generate a QR code and return the visual representation as a string
///
/// This function creates a QR code from the provided data and returns it as
/// a string that can be printed to the console.
///
/// # Arguments
/// * `data` - The data to encode (must implement Serialize)
/// * `options` - Display options for the QR code
///
/// # Returns
/// * `QrResult<String>` - The QR code as a printable string
///
/// # Examples
/// ```
/// use zoe_app_primitives::qr::{generate_qr_string, QrOptions};
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct MyData {
///     message: String,
/// }
///
/// let data = MyData { message: "Hello, World!".to_string() };
/// let options = QrOptions::new("My QR Code").with_footer("Scan me!");
/// let qr_string = generate_qr_string(&data, &options).unwrap();
/// println!("{}", qr_string);
/// ```
pub fn generate_qr_string<T: Serialize>(data: &T, options: &QrOptions) -> QrResult<String> {
    let qr_data = generate_qr_data(data)?;
    let qr_code = QrCode::new(&qr_data[..])?;

    let image = qr_code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();

    let mut result = String::new();
    let border_char = "─";
    let border = border_char.repeat(options.border_width);

    // Top border
    result.push_str(&format!("┌{}┐\n", border));

    // Title
    result.push_str(&format!(
        "│{:^width$}│\n",
        options.title,
        width = options.border_width
    ));

    // Subtitle lines
    if !options.subtitle_lines.is_empty() {
        result.push_str(&format!("├{}┤\n", border));
        for subtitle in &options.subtitle_lines {
            result.push_str(&format!(
                "│{:^width$}│\n",
                subtitle,
                width = options.border_width
            ));
        }
    }

    // Separator before QR code
    result.push_str(&format!("├{}┤\n", border));

    // QR code
    for line in image.lines() {
        let padded_line = format!("{line:^width$}", width = options.border_width - 2);
        result.push_str(&format!("│{padded_line}│\n"));
    }

    // Separator after QR code
    result.push_str(&format!("├{}┤\n", border));

    // Footer
    result.push_str(&format!(
        "│{:^width$}│\n",
        options.footer,
        width = options.border_width
    ));

    // Bottom border
    result.push_str(&format!("└{}┘", border));

    Ok(result)
}

/// Display a QR code to stdout
///
/// This is a convenience function that generates and prints a QR code directly.
///
/// # Arguments
/// * `data` - The data to encode (must implement Serialize)
/// * `options` - Display options for the QR code
///
/// # Returns
/// * `QrResult<()>` - Success or error
///
/// # Examples
/// ```
/// use zoe_app_primitives::qr::{display_qr_code, QrOptions};
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct MyData {
///     message: String,
/// }
///
/// let data = MyData { message: "Hello, World!".to_string() };
/// let options = QrOptions::new("My QR Code").with_footer("Scan me!");
/// display_qr_code(&data, &options).unwrap();
/// ```
pub fn display_qr_code<T: Serialize>(data: &T, options: &QrOptions) -> QrResult<()> {
    let qr_string = generate_qr_string(data, options)?;
    println!("{}", qr_string);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestData {
        message: String,
        number: u32,
    }

    #[test]
    fn test_generate_qr_data() {
        let data = TestData {
            message: "Hello, World!".to_string(),
            number: 42,
        };

        let qr_data = generate_qr_data(&data).unwrap();

        // Verify we can decode the binary data back directly
        let decoded_data: TestData = postcard::from_bytes(&qr_data).unwrap();

        assert_eq!(data, decoded_data);
    }

    #[test]
    fn test_generate_qr_string() {
        let data = TestData {
            message: "Test".to_string(),
            number: 123,
        };

        let options = QrOptions::new("Test QR Code")
            .with_subtitle("Subtitle line")
            .with_footer("Test footer");

        let qr_string = generate_qr_string(&data, &options).unwrap();

        // Verify the string contains expected elements
        assert!(qr_string.contains("Test QR Code"));
        assert!(qr_string.contains("Subtitle line"));
        assert!(qr_string.contains("Test footer"));
        assert!(qr_string.contains("┌"));
        assert!(qr_string.contains("└"));
    }

    #[test]
    fn test_qr_options_builder() {
        let options = QrOptions::new("My Title")
            .with_subtitle("Line 1")
            .with_subtitle("Line 2")
            .with_footer("My Footer")
            .with_border_width(80);

        assert_eq!(options.title, "My Title");
        assert_eq!(options.subtitle_lines, vec!["Line 1", "Line 2"]);
        assert_eq!(options.footer, "My Footer");
        assert_eq!(options.border_width, 80);
    }

    #[test]
    fn test_qr_options_default() {
        let options = QrOptions::default();

        assert_eq!(options.title, "QR CODE");
        assert!(options.subtitle_lines.is_empty());
        assert_eq!(options.footer, "Scan to connect");
        assert_eq!(options.border_width, 60);
    }
    #[test]
    fn test_empty_data_serialization() {
        #[derive(Serialize, Deserialize)]
        struct EmptyData;

        let data = EmptyData;
        let qr_data = generate_qr_data(&data).unwrap();

        // Empty structs in postcard serialize to empty bytes
        // This is correct behavior - empty data should produce empty binary data
        assert_eq!(qr_data, Vec::<u8>::new());

        // Verify we can still decode empty data back
        let _decoded_data: EmptyData = postcard::from_bytes(&qr_data).unwrap();
    }

    #[test]
    fn test_large_data_serialization() {
        let data = TestData {
            message: "A".repeat(1000), // Large string
            number: u32::MAX,
        };

        let qr_data = generate_qr_data(&data).unwrap();

        // Verify we can still decode large data directly from binary
        let decoded_data: TestData = postcard::from_bytes(&qr_data).unwrap();

        assert_eq!(data, decoded_data);
    }

    #[test]
    fn test_qr_string_formatting() {
        let data = TestData {
            message: "Format test".to_string(),
            number: 789,
        };

        let options = QrOptions::new("📱 TITLE")
            .with_subtitle("Address: 192.168.1.1:8080")
            .with_subtitle("Key: abc123...")
            .with_footer("Scan with app to connect")
            .with_border_width(50);

        let qr_string = generate_qr_string(&data, &options).unwrap();

        // Check that all components are present and properly formatted
        let lines: Vec<&str> = qr_string.lines().collect();

        // Should have top border
        assert!(lines[0].starts_with("┌"));
        assert!(lines[0].ends_with("┐"));

        // Should have title
        assert!(lines[1].contains("📱 TITLE"));

        // Should have subtitles
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Address: 192.168.1.1:8080"))
        );
        assert!(lines.iter().any(|line| line.contains("Key: abc123...")));

        // Should have footer
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Scan with app to connect"))
        );

        // Should have bottom border
        let last_line = lines.last().unwrap();
        assert!(last_line.starts_with("└"));
        assert!(last_line.ends_with("┘"));
    }
}
