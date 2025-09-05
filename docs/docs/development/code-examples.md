# Code Import Examples

This page demonstrates different ways to include code in Docusaurus documentation.

## Method 1: Manual Code Blocks

The simplest approach is to manually write code blocks:

```rust title="Manual Example"
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleStruct {
    pub field1: String,
    pub field2: u32,
}
```

## Method 2: Import Entire Files

Import and display entire source files using raw-loader:

import CodeBlock from '@theme/CodeBlock';
import InvitationSource from '!!raw-loader!../../../crates/wire-protocol/src/invitation.rs';

<CodeBlock language="rust" title="crates/wire-protocol/src/invitation.rs" showLineNumbers>
{InvitationSource}
</CodeBlock>

## Method 3: Collapsible Code Sections

Use details/summary for large code blocks:

<details>
<summary>Click to view full implementation</summary>

import AppPrimitivesSource from '!!raw-loader!../../../crates/app-primitives/src/invitation.rs';

<CodeBlock language="rust" title="crates/app-primitives/src/invitation.rs">
{AppPrimitivesSource}
</CodeBlock>

</details>

## Method 4: Code Tabs

Show multiple related files using tabs:

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="invitation" label="Invitation Types" default>

```rust title="crates/wire-protocol/src/invitation.rs (excerpt)"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationHandshakeRequest {
    pub protocol_version: ProtocolVersion,
    pub purpose: HandshakePurpose,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub success: bool,
    pub emoji_sequence: [String; 6],
}
```

  </TabItem>
  <TabItem value="primitives" label="Crypto Primitives">

```rust title="crates/app-primitives/src/invitation.rs (excerpt)"
pub const EMOJI_SET: [&str; 64] = [
    "🎯", "🚀", "⭐", "🔥", "💎", "🌟", "⚡", "🎨",
    "🎭", "🎪", "🎨", "🎯", "🎲", "🎸", "🎺", "🎻",
    // ... more emojis
];

pub fn derive_emoji_verification(shared_secret: &[u8]) -> [&'static str; 6] {
    // Implementation here...
}
```

  </TabItem>
</Tabs>

## Method 5: Inline Code with Highlighting

Highlight specific lines in code blocks:

```rust title="Example with highlighted lines" {2,5-7}
use blake3::Hasher;
use serde::{Deserialize, Serialize}; // This line is highlighted

pub fn example_function() {
    let mut hasher = Hasher::new();           // These lines
    hasher.update(b"domain-separation");     // are also
    let result = hasher.finalize();          // highlighted
}
```

## Method 6: Live Code Playground

For interactive examples, you can link to the Rust Playground:

```rust title="Try this in Rust Playground"
fn main() {
    println!("Hello from Zoe Relay!");
    
    // Example of emoji verification
    let emojis = ["🎯", "🚀", "⭐", "🔥", "💎", "🌟"];
    println!("Verification emojis: {:?}", emojis);
}
```

[**▶️ Run this code in Rust Playground**](https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&code=fn%20main()%20%7B%0A%20%20%20%20println!(%22Hello%20from%20Zoe%20Relay!%22)%3B%0A%20%20%20%20%0A%20%20%20%20%2F%2F%20Example%20of%20emoji%20verification%0A%20%20%20%20let%20emojis%20%3D%20%5B%22%F0%9F%8E%AF%22%2C%20%22%F0%9F%9A%80%22%2C%20%22%E2%AD%90%22%2C%20%22%F0%9F%94%A5%22%2C%20%22%F0%9F%92%8E%22%2C%20%22%F0%9F%8C%9F%22%5D%3B%0A%20%20%20%20println!(%22Verification%20emojis%3A%20%7B%3A%3F%7D%22%2C%20emojis)%3B%0A%7D)

## Best Practices

### When to Use Each Method:

1. **Manual Code Blocks**: For examples, pseudocode, or simplified versions
2. **File Import**: When you want to show the actual implementation
3. **Collapsible Sections**: For large files that might overwhelm the page
4. **Tabs**: When showing related files or different approaches
5. **Line Highlighting**: To draw attention to specific parts
6. **Playground Links**: For runnable examples

### Tips:

- Use `title` attribute to show file paths
- Use `showLineNumbers` for longer code blocks
- Use `{1,3-5}` syntax to highlight specific lines
- Keep manual examples concise and focused
- Use collapsible sections for reference implementations

## Configuration

To use raw-loader imports, make sure you have it installed:

```bash
npm install --save raw-loader
```

Then import files using the `!!raw-loader!` prefix:

```javascript
import SourceCode from '!!raw-loader!../../path/to/file.rs';
```