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
        // Calculate the visual width of the QR line (Unicode characters may have different widths)
        let line_visual_width = line.chars().count();

        // Calculate padding needed to center the QR code within the border
        let total_padding = options.border_width.saturating_sub(line_visual_width);
        let left_padding = total_padding / 2;
        let right_padding = total_padding - left_padding;

        // Create the padded line with proper spacing
        let padded_line = format!(
            "{}{}{}",
            " ".repeat(left_padding),
            line,
            " ".repeat(right_padding)
        );

        result.push_str(&format!("│{}│\n", padded_line));
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

    #[test]
    fn test_qr_line_formatting_consistency() {
        let data = TestData {
            message: "Test".to_string(),
            number: 42,
        };

        let options = QrOptions::new("TEST").with_border_width(60);

        let qr_string = generate_qr_string(&data, &options).unwrap();
        let lines: Vec<&str> = qr_string.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            // Each line should start and end with border characters
            assert!(
                line.starts_with('│')
                    || line.starts_with('┌')
                    || line.starts_with('├')
                    || line.starts_with('└'),
                "Line {} should start with border character: '{}'",
                i,
                line
            );
            assert!(
                line.ends_with('│')
                    || line.ends_with('┐')
                    || line.ends_with('┤')
                    || line.ends_with('┘'),
                "Line {} should end with border character: '{}'",
                i,
                line
            );

            // Check that QR code lines are properly formatted
            if line.starts_with('│') && !line.contains("TEST") && !line.contains("Scan to connect")
            {
                // This should be a QR code line - verify it's properly padded
                // Extract content by removing the first and last characters (the │ borders)
                let chars: Vec<char> = line.chars().collect();
                if chars.len() >= 2 {
                    let content: String = chars[1..chars.len() - 1].iter().collect();
                    assert_eq!(
                        content.chars().count(),
                        options.border_width,
                        "QR line {} content should be exactly {} characters: '{}'",
                        i,
                        options.border_width,
                        content
                    );
                }
            }
        }
    }

    #[test]
    fn test_qr_centering_with_different_border_widths() {
        let data = TestData {
            message: "Centering test".to_string(),
            number: 999,
        };

        // Test with various border widths
        for border_width in [40, 50, 60, 70, 80] {
            let options = QrOptions::new("CENTERING TEST").with_border_width(border_width);

            let qr_string = generate_qr_string(&data, &options).unwrap();
            let lines: Vec<&str> = qr_string.lines().collect();

            // Find QR code lines and verify they're properly centered
            for line in &lines {
                if line.starts_with('│')
                    && !line.contains("CENTERING TEST")
                    && !line.contains("Scan to connect")
                {
                    let chars: Vec<char> = line.chars().collect();
                    if chars.len() >= 2 {
                        let content: String = chars[1..chars.len() - 1].iter().collect();
                        assert_eq!(
                            content.chars().count(),
                            border_width,
                            "Content width should match border_width {} for line: '{}'",
                            border_width,
                            content
                        );

                        // Verify the QR code is centered by checking that leading and trailing spaces are balanced
                        let trimmed = content.trim();
                        if !trimmed.is_empty() {
                            let leading_spaces = content.len() - content.trim_start().len();
                            let trailing_spaces = content.len() - content.trim_end().len();
                            // Allow for ±1 difference due to odd/even width differences
                            assert!(
                                (leading_spaces as i32 - trailing_spaces as i32).abs() <= 1,
                                "QR code should be centered: leading={}, trailing={}, content='{}'",
                                leading_spaces,
                                trailing_spaces,
                                content
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_qr_visual_output_sample() {
        let data = TestData {
            message: "Visual test".to_string(),
            number: 12345,
        };

        let options = QrOptions::new("📡 ZOE RELAY SERVER")
            .with_subtitle("Bind: 127.0.0.1:13908")
            .with_subtitle("Key: 75cbe0f409466428...")
            .with_footer("Scan with Zoe client to connect")
            .with_border_width(60);

        let qr_string = generate_qr_string(&data, &options).unwrap();

        // Print the QR code for visual inspection during development
        // This helps ensure the output looks correct
        println!("Generated QR code:");
        println!("{}", qr_string);

        // Verify structure
        let lines: Vec<&str> = qr_string.lines().collect();
        assert!(!lines.is_empty(), "QR string should have content");

        // Should contain all expected text elements
        let full_text = qr_string;
        assert!(full_text.contains("📡 ZOE RELAY SERVER"));
        assert!(full_text.contains("Bind: 127.0.0.1:13908"));
        assert!(full_text.contains("Key: 75cbe0f409466428..."));
        assert!(full_text.contains("Scan with Zoe client to connect"));

        // Should have proper border structure
        assert!(full_text.contains("┌"));
        assert!(full_text.contains("└"));
        assert!(full_text.contains("├"));
        assert!(full_text.contains("┤"));
    }
}
