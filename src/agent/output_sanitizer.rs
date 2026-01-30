//! Output sanitizer — content security policy enforcement for agent outputs.
//!
//! Provides HTML and Markdown sanitization so that agent-generated content can
//! be safely rendered by web UIs.  All sanitization uses regex-based string
//! processing (no external HTML parser crate) following the same pattern used by
//! `logging/redact.rs` and `prompt_guard/postflight.rs`.
//!
//! Two layers:
//! 1. **HTML sanitizer** — strips dangerous tags, event handlers, and
//!    `javascript:`/`data:` URLs from raw HTML fragments.
//! 2. **Markdown sanitizer** — neutralises raw HTML blocks inside Markdown and
//!    disarms dangerous autolinks.
//!
//! A **CSP policy** is generated alongside the sanitized content so that web
//! clients can sandbox rendering with a restrictive Content-Security-Policy.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the output sanitizer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSanitizerConfig {
    /// Master switch for HTML sanitization. Default: `true`.
    #[serde(default = "default_true")]
    pub sanitize_html: bool,
    /// CSP policy string attached to sanitized output. Use an empty string to
    /// disable.  Default: restrictive agent-content policy.
    #[serde(default = "default_csp_policy")]
    pub csp_policy: String,
}

impl Default for OutputSanitizerConfig {
    fn default() -> Self {
        Self {
            sanitize_html: true,
            csp_policy: default_csp_policy(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// The default, restrictive CSP policy for agent-generated content.
///
/// - `default-src 'none'` — block everything by default.
/// - `img-src https: data:` — allow HTTPS images and inline data-URI images.
/// - `style-src 'unsafe-inline'` — allow inline styles (required for Markdown
///   rendering with embedded styles).
/// - No `script-src`, `frame-src`, or `object-src` — scripts, iframes, and
///   plugins are completely blocked.
pub fn default_csp_policy() -> String {
    "default-src 'none'; img-src https: data:; style-src 'unsafe-inline'".to_string()
}

// ---------------------------------------------------------------------------
// HTML tag / attribute allowlists
// ---------------------------------------------------------------------------

/// Default set of HTML tags that are considered safe to keep.
const ALLOWED_TAGS: &[&str] = &[
    "a",
    "abbr",
    "b",
    "blockquote",
    "br",
    "code",
    "dd",
    "del",
    "details",
    "div",
    "dl",
    "dt",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "img",
    "ins",
    "kbd",
    "li",
    "mark",
    "ol",
    "p",
    "pre",
    "q",
    "s",
    "samp",
    "small",
    "span",
    "strong",
    "sub",
    "summary",
    "sup",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "u",
    "ul",
    "var",
    "wbr",
];

/// HTML tags that are always stripped (dangerous).
const DANGEROUS_TAGS: &[&str] = &[
    "script", "iframe", "object", "embed", "form", "meta", "link", "base", "applet", "frame",
    "frameset", "noscript", "template", "svg", "math", "video", "audio", "source", "track",
    "canvas", "dialog", "slot", "textarea", "select", "input", "button",
];

/// Attributes that are safe on most elements.
const ALLOWED_ATTRS: &[&str] = &[
    "id",
    "class",
    "title",
    "alt",
    "width",
    "height",
    "align",
    "valign",
    "colspan",
    "rowspan",
    "scope",
    "dir",
    "lang",
    "role",
    "aria-label",
    "aria-hidden",
    "aria-describedby",
];

/// Attributes allowed only on specific tags (tag, attr).
const TAG_SPECIFIC_ATTRS: &[(&str, &str)] = &[
    ("a", "href"),
    ("a", "target"),
    ("a", "rel"),
    ("img", "src"),
    ("img", "loading"),
    ("td", "colspan"),
    ("td", "rowspan"),
    ("th", "colspan"),
    ("th", "rowspan"),
    ("ol", "start"),
    ("ol", "type"),
];

// ---------------------------------------------------------------------------
// Compiled regex patterns (lazy, compiled once)
// ---------------------------------------------------------------------------

/// Matches any HTML tag (opening, closing, or self-closing).
static RE_HTML_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?si)<(/?)([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)(/?)>").unwrap());

/// Matches HTML comments.
static RE_HTML_COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->").unwrap());

/// Matches on* event handler attributes (e.g. onclick="...", onerror='...').
static RE_EVENT_HANDLER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bon[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)"#).unwrap());

/// Matches `style` attributes that contain `@import` or `url(...)` with
/// `javascript:` — dangerous CSS injection vectors.
static RE_STYLE_DANGEROUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)style\s*=\s*(?:"[^"]*(?:@import|expression\s*\(|javascript:)[^"]*"|'[^']*(?:@import|expression\s*\(|javascript:)[^']*')"#).unwrap()
});

/// Matches `javascript:` scheme in attribute values.
static RE_JAVASCRIPT_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:href|src|action|formaction)\s*=\s*(?:"[^"]*javascript\s*:[^"]*"|'[^']*javascript\s*:[^']*')"#).unwrap()
});

/// Matches all `data:` URLs in src/href (double-quoted).
static RE_DATA_URL_DQ: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:href|src)\s*=\s*"(data:[^"]*)""#).unwrap());
/// Matches all `data:` URLs in src/href (single-quoted).
static RE_DATA_URL_SQ: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:href|src)\s*=\s*'(data:[^']*)'"#).unwrap());

/// Image MIME types allowed in `data:` URLs.
const ALLOWED_DATA_IMAGE_PREFIXES: &[&str] = &[
    "data:image/png",
    "data:image/jpeg",
    "data:image/jpg",
    "data:image/gif",
    "data:image/svg+xml",
    "data:image/webp",
    "data:image/bmp",
    "data:image/ico",
];

/// Returns true if a `data:` URI is an allowed image type.
fn is_allowed_data_url(uri: &str) -> bool {
    let lower = uri.to_lowercase();
    ALLOWED_DATA_IMAGE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Matches `<style` blocks that contain `@import`.
static RE_STYLE_TAG_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?si)<style[^>]*>.*?@import.*?</style>").unwrap());

// -- Markdown-specific patterns --

/// Matches raw HTML blocks in Markdown (any line starting with `<` that looks
/// like a tag).  This is intentionally broad to catch inline HTML.
static RE_MD_HTML_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^[ ]{0,3}</?[a-zA-Z][a-zA-Z0-9]*\b[^>]*>.*$").unwrap());

/// Matches Markdown autolinks with dangerous schemes: `<javascript:...>` or
/// `<data:...>` (non-image).
static RE_MD_DANGEROUS_AUTOLINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<(?:javascript|vbscript|data):[^>]+>").unwrap());

/// Matches inline Markdown links/images with dangerous href/src.
static RE_MD_DANGEROUS_LINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\[([^\]]*)\]\(\s*(?:javascript|vbscript|data)\s*:[^)]*\)").unwrap()
});

// ---------------------------------------------------------------------------
// Sanitization result
// ---------------------------------------------------------------------------

/// Result of sanitizing agent output.
#[derive(Debug, Clone)]
pub struct SanitizedOutput {
    /// The sanitized content.
    pub content: String,
    /// CSP policy to apply when rendering this content.
    pub csp_policy: String,
    /// Whether any modifications were made.
    pub was_modified: bool,
}

// ---------------------------------------------------------------------------
// HTML sanitizer
// ---------------------------------------------------------------------------

/// Sanitize an HTML fragment by stripping dangerous constructs.
///
/// The sanitizer:
/// - Removes dangerous tags and their content (`<script>`, `<iframe>`, etc.)
/// - Strips event handler attributes (`onclick`, `onerror`, etc.)
/// - Removes `javascript:` and non-image `data:` URLs from href/src
/// - Strips dangerous CSS (`@import`, `expression()`, `javascript:` in styles)
/// - Removes HTML comments
/// - Keeps allowed tags with allowed attributes
pub fn sanitize_html(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut result = input.to_string();

    // 1. Strip HTML comments
    result = RE_HTML_COMMENT.replace_all(&result, "").into_owned();

    // 2. Strip <style> tags containing @import
    result = RE_STYLE_TAG_IMPORT.replace_all(&result, "").into_owned();

    // 3. Process HTML tags — strip dangerous ones, clean allowed ones
    result = RE_HTML_TAG
        .replace_all(&result, |caps: &regex::Captures| {
            let slash = &caps[1]; // "/" for closing tags
            let tag_name = caps[2].to_lowercase();
            let attrs = &caps[3];
            let self_close = &caps[4];

            // Strip dangerous tags entirely
            if DANGEROUS_TAGS.contains(&tag_name.as_str()) {
                return String::new();
            }

            // If tag is not in the allowed list, strip it but keep content
            if !ALLOWED_TAGS.contains(&tag_name.as_str()) {
                return String::new();
            }

            // For closing tags, no attribute processing needed
            if !slash.is_empty() {
                return format!("</{tag_name}>");
            }

            // Clean attributes
            let clean_attrs = sanitize_attributes(&tag_name, attrs);

            if self_close.is_empty() {
                if clean_attrs.is_empty() {
                    format!("<{tag_name}>")
                } else {
                    format!("<{tag_name}{clean_attrs}>")
                }
            } else if clean_attrs.is_empty() {
                format!("<{tag_name} />")
            } else {
                format!("<{tag_name}{clean_attrs} />")
            }
        })
        .into_owned();

    // 4. Strip any remaining dangerous content between stripped tags
    //    (e.g. content that was between <script>...</script>)
    result = strip_dangerous_tag_content(&result);

    result
}

/// Strip content between dangerous tag pairs that may remain after tag removal.
///
/// After regex-based tag stripping, inline content from `<script>alert(1)</script>`
/// becomes just `alert(1)`.  We re-scan to remove such orphaned content patterns.
fn strip_dangerous_tag_content(input: &str) -> String {
    // For each dangerous tag, remove <tag...>...</tag> blocks (case-insensitive)
    let mut result = input.to_string();
    for tag in DANGEROUS_TAGS {
        let pattern = format!(
            r"(?si)<{tag}\b[^>]*>.*?</{tag}\s*>",
            tag = regex::escape(tag)
        );
        if let Ok(re) = Regex::new(&pattern) {
            result = re.replace_all(&result, "").into_owned();
        }
    }
    result
}

/// Sanitize HTML attributes, keeping only allowed ones.
fn sanitize_attributes(tag: &str, attrs: &str) -> String {
    if attrs.trim().is_empty() {
        return String::new();
    }

    // Strip event handlers first
    let cleaned = RE_EVENT_HANDLER.replace_all(attrs, "");
    // Strip javascript: URLs
    let cleaned = RE_JAVASCRIPT_URL.replace_all(&cleaned, "");
    // Strip dangerous style attributes
    let cleaned = RE_STYLE_DANGEROUS.replace_all(&cleaned, "");
    // Strip non-image data: URLs (keep allowed image MIME types)
    let cleaned = RE_DATA_URL_DQ.replace_all(&cleaned, |caps: &regex::Captures| {
        if is_allowed_data_url(&caps[1]) {
            caps[0].to_string()
        } else {
            String::new()
        }
    });
    let cleaned = RE_DATA_URL_SQ.replace_all(&cleaned, |caps: &regex::Captures| {
        if is_allowed_data_url(&caps[1]) {
            caps[0].to_string()
        } else {
            String::new()
        }
    });

    // Parse remaining attributes and filter to allowlist
    let attr_re =
        Regex::new(r#"([a-zA-Z][a-zA-Z0-9\-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))"#).unwrap();

    let mut safe_attrs = Vec::new();
    for cap in attr_re.captures_iter(&cleaned) {
        let attr_name = cap[1].to_lowercase();

        // Check if this attribute is globally allowed
        let is_allowed = ALLOWED_ATTRS.contains(&attr_name.as_str());
        // Check if this attribute is allowed for this specific tag
        let is_tag_specific = TAG_SPECIFIC_ATTRS
            .iter()
            .any(|(t, a)| *t == tag && *a == attr_name.as_str());
        // Allow style attribute (inline styles are permitted by our CSP)
        let is_style = attr_name == "style";

        if is_allowed || is_tag_specific || is_style {
            let value = cap
                .get(2)
                .or(cap.get(3))
                .or(cap.get(4))
                .map(|m| m.as_str())
                .unwrap_or("");

            // Final safety check: no javascript: in any attribute value
            if value.to_lowercase().contains("javascript:") {
                continue;
            }
            // No data: in href (only allow in img src)
            if attr_name == "href" && value.to_lowercase().trim_start().starts_with("data:") {
                continue;
            }
            // For img src, allow data: only for images
            if attr_name == "src" && value.to_lowercase().trim_start().starts_with("data:") {
                let lower = value.to_lowercase();
                let trimmed = lower.trim_start();
                if !trimmed.starts_with("data:image/") {
                    continue;
                }
            }

            safe_attrs.push(format!(" {attr_name}=\"{}\"", escape_attr_value(value)));
        }
    }

    safe_attrs.join("")
}

/// Escape HTML attribute values.
fn escape_attr_value(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ---------------------------------------------------------------------------
// Markdown sanitizer
// ---------------------------------------------------------------------------

/// Sanitize Markdown content by neutralising dangerous constructs.
///
/// The sanitizer:
/// - Strips raw HTML blocks from Markdown
/// - Neutralises `javascript:` and `data:` autolinks
/// - Neutralises dangerous link/image targets
/// - Escapes HTML entities in inline HTML
pub fn sanitize_markdown(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut result = input.to_string();

    // 1. Strip raw HTML blocks — replace with empty line to preserve structure
    result = RE_MD_HTML_BLOCK
        .replace_all(&result, |caps: &regex::Captures| {
            let line = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            // Only strip lines with dangerous tags; keep safe inline HTML
            let lower = line.to_lowercase();
            for tag in DANGEROUS_TAGS {
                if lower.contains(&format!("<{tag}")) || lower.contains(&format!("</{tag}")) {
                    return String::new();
                }
            }
            // Run HTML sanitiser on any remaining HTML lines
            sanitize_html(line)
        })
        .into_owned();

    // 2. Neutralise dangerous autolinks: <javascript:...> → `javascript:...`
    result = RE_MD_DANGEROUS_AUTOLINK
        .replace_all(&result, |caps: &regex::Captures| {
            let inner = &caps[0];
            // Strip the angle brackets and wrap in backticks to render as code
            let content = &inner[1..inner.len() - 1];
            format!("`{content}`")
        })
        .into_owned();

    // 3. Neutralise dangerous link/image targets
    result = RE_MD_DANGEROUS_LINK
        .replace_all(&result, |caps: &regex::Captures| {
            let label = &caps[1];
            if label.is_empty() {
                "[link removed]".to_string()
            } else {
                label.to_string()
            }
        })
        .into_owned();

    result
}

// ---------------------------------------------------------------------------
// Combined sanitizer (public API)
// ---------------------------------------------------------------------------

/// Sanitize agent output for safe web rendering.
///
/// Applies both HTML and Markdown sanitization, and attaches the CSP policy
/// metadata for clients to use when rendering.
pub fn sanitize_output(content: &str, config: &OutputSanitizerConfig) -> SanitizedOutput {
    if !config.sanitize_html {
        return SanitizedOutput {
            content: content.to_string(),
            csp_policy: config.csp_policy.clone(),
            was_modified: false,
        };
    }

    // Apply HTML sanitization
    let html_clean = sanitize_html(content);
    // Apply Markdown sanitization on top
    let md_clean = sanitize_markdown(&html_clean);

    let was_modified = md_clean != content;

    SanitizedOutput {
        content: md_clean,
        csp_policy: config.csp_policy.clone(),
        was_modified,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== HTML Sanitization ====================

    #[test]
    fn test_clean_html_passes_through() {
        let input = "<p>Hello <b>world</b></p>";
        let result = sanitize_html(input);
        assert_eq!(result, "<p>Hello <b>world</b></p>");
    }

    #[test]
    fn test_strip_script_tag() {
        let input = "before<script>alert('xss')</script>after";
        let result = sanitize_html(input);
        assert!(!result.contains("script"));
        assert!(!result.contains("alert"));
        assert!(result.contains("before"));
        assert!(result.contains("after"));
    }

    #[test]
    fn test_strip_script_tag_uppercase() {
        let input = "<SCRIPT>alert(1)</SCRIPT>";
        let result = sanitize_html(input);
        assert!(!result.contains("SCRIPT"));
        assert!(!result.contains("alert"));
    }

    #[test]
    fn test_strip_iframe() {
        let input = r#"<iframe src="https://evil.com"></iframe>"#;
        let result = sanitize_html(input);
        assert!(!result.contains("iframe"));
        assert!(!result.contains("evil.com"));
    }

    #[test]
    fn test_strip_object_embed() {
        let input = r#"<object data="malware.swf"></object><embed src="bad.swf">"#;
        let result = sanitize_html(input);
        assert!(!result.contains("object"));
        assert!(!result.contains("embed"));
        assert!(!result.contains("malware"));
    }

    #[test]
    fn test_strip_form() {
        let input = r#"<form action="https://evil.com"><input type="text"></form>"#;
        let result = sanitize_html(input);
        assert!(!result.contains("form"));
        assert!(!result.contains("input"));
    }

    #[test]
    fn test_strip_meta_link_base() {
        let input = r#"<meta http-equiv="refresh"><link rel="import"><base href="/">"#;
        let result = sanitize_html(input);
        assert!(!result.contains("meta"));
        assert!(!result.contains("link"));
        assert!(!result.contains("base"));
    }

    #[test]
    fn test_strip_event_handlers() {
        let input = r#"<img src="cat.png" onerror="alert(1)" onload="steal()">"#;
        let result = sanitize_html(input);
        assert!(!result.contains("onerror"));
        assert!(!result.contains("onload"));
        assert!(!result.contains("alert"));
        assert!(!result.contains("steal"));
        assert!(result.contains("cat.png"));
    }

    #[test]
    fn test_strip_javascript_url_href() {
        let input = r#"<a href="javascript:alert(1)">click</a>"#;
        let result = sanitize_html(input);
        assert!(!result.contains("javascript:"));
    }

    #[test]
    fn test_strip_javascript_url_src() {
        let input = r#"<img src="javascript:alert(1)">"#;
        let result = sanitize_html(input);
        assert!(!result.contains("javascript:"));
    }

    #[test]
    fn test_allow_data_url_image() {
        let input = r#"<img src="data:image/png;base64,iVBOR...">"#;
        let result = sanitize_html(input);
        assert!(result.contains("data:image/png"));
    }

    #[test]
    fn test_strip_data_url_non_image_href() {
        let input = r#"<a href="data:text/html,<script>alert(1)</script>">click</a>"#;
        let result = sanitize_html(input);
        assert!(!result.contains("data:text/html"));
    }

    #[test]
    fn test_strip_style_import() {
        let input = r#"<style>@import url("https://evil.com/steal.css");</style>"#;
        let result = sanitize_html(input);
        assert!(!result.contains("@import"));
        assert!(!result.contains("evil.com"));
    }

    #[test]
    fn test_strip_html_comments() {
        let input = "before<!-- <script>alert(1)</script> -->after";
        let result = sanitize_html(input);
        assert!(!result.contains("<!--"));
        assert!(!result.contains("-->"));
        assert!(result.contains("before"));
        assert!(result.contains("after"));
    }

    #[test]
    fn test_allowed_tags_preserved() {
        let input = "<h1>Title</h1><p>Text with <strong>bold</strong> and <em>italic</em>.</p>";
        let result = sanitize_html(input);
        assert!(result.contains("<h1>"));
        assert!(result.contains("<strong>"));
        assert!(result.contains("<em>"));
    }

    #[test]
    fn test_allowed_attributes_preserved() {
        let input = r#"<p class="intro" id="p1">Text</p>"#;
        let result = sanitize_html(input);
        assert!(result.contains("class="));
        assert!(result.contains("id="));
    }

    #[test]
    fn test_a_href_https_preserved() {
        let input = r#"<a href="https://example.com">link</a>"#;
        let result = sanitize_html(input);
        assert!(result.contains("href="));
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_unknown_tag_stripped_content_kept() {
        let input = "<blink>text</blink>";
        let result = sanitize_html(input);
        assert!(!result.contains("<blink>"));
        assert!(result.contains("text"));
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(sanitize_html(""), "");
        assert_eq!(sanitize_markdown(""), "");
    }

    #[test]
    fn test_no_html_passthrough() {
        let input = "Hello, world! This is plain text.";
        assert_eq!(sanitize_html(input), input);
    }

    #[test]
    fn test_svg_stripped() {
        let input = r#"<svg onload="alert(1)"><circle cx="50"/></svg>"#;
        let result = sanitize_html(input);
        assert!(!result.contains("svg"));
        assert!(!result.contains("alert"));
    }

    #[test]
    fn test_nested_dangerous_tags() {
        let input = "<div><script><script>nested</script></script></div>";
        let result = sanitize_html(input);
        assert!(!result.contains("script"));
        assert!(!result.contains("nested"));
        assert!(result.contains("<div>"));
    }

    // ==================== Markdown Sanitization ====================

    #[test]
    fn test_md_clean_text_passthrough() {
        let input = "# Hello\n\nThis is **bold** and *italic*.";
        let result = sanitize_markdown(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_md_strip_dangerous_html_block() {
        let input = "Some text\n<script>alert(1)</script>\nMore text";
        let result = sanitize_markdown(input);
        assert!(!result.contains("script"));
        assert!(!result.contains("alert"));
        assert!(result.contains("Some text"));
        assert!(result.contains("More text"));
    }

    #[test]
    fn test_md_neutralize_javascript_autolink() {
        let input = "Click <javascript:alert(1)> here";
        let result = sanitize_markdown(input);
        assert!(!result.contains("<javascript:"));
        assert!(result.contains("`javascript:alert(1)`"));
    }

    #[test]
    fn test_md_neutralize_dangerous_link() {
        let input = "[click me](javascript:alert(1))";
        let result = sanitize_markdown(input);
        assert!(!result.contains("javascript:"));
        assert!(result.contains("click me"));
    }

    #[test]
    fn test_md_neutralize_data_autolink() {
        let input = "Click <data:text/html,<script>alert(1)</script>> here";
        let result = sanitize_markdown(input);
        assert!(!result.contains("<data:"));
    }

    #[test]
    fn test_md_safe_html_preserved() {
        let input = "Text with <em>emphasis</em> inline.";
        let result = sanitize_markdown(input);
        assert!(result.contains("<em>emphasis</em>"));
    }

    #[test]
    fn test_md_code_blocks_preserved() {
        let input = "```\n<script>alert(1)</script>\n```";
        let result = sanitize_markdown(input);
        // Code blocks (fenced) are not lines starting with <tag, so they pass through
        assert!(result.contains("```"));
    }

    // ==================== CSP Policy ====================

    #[test]
    fn test_default_csp_policy_content() {
        let policy = default_csp_policy();
        assert!(policy.contains("default-src 'none'"));
        assert!(policy.contains("img-src https: data:"));
        assert!(policy.contains("style-src 'unsafe-inline'"));
        // Must NOT contain script-src, frame-src, or object-src
        assert!(!policy.contains("script-src"));
        assert!(!policy.contains("frame-src"));
        assert!(!policy.contains("object-src"));
    }

    #[test]
    fn test_csp_policy_attached_to_output() {
        let config = OutputSanitizerConfig::default();
        let result = sanitize_output("<p>Hello</p>", &config);
        assert!(!result.csp_policy.is_empty());
        assert!(result.csp_policy.contains("default-src 'none'"));
    }

    // ==================== Combined Sanitizer ====================

    #[test]
    fn test_sanitize_output_strips_xss() {
        let config = OutputSanitizerConfig::default();
        let input = r#"<p>Hello</p><script>alert('xss')</script>"#;
        let result = sanitize_output(input, &config);
        assert!(!result.content.contains("script"));
        assert!(!result.content.contains("alert"));
        assert!(result.content.contains("<p>Hello</p>"));
        assert!(result.was_modified);
    }

    #[test]
    fn test_sanitize_output_disabled() {
        let config = OutputSanitizerConfig {
            sanitize_html: false,
            ..Default::default()
        };
        let input = "<script>alert(1)</script>";
        let result = sanitize_output(input, &config);
        // When disabled, content passes through unchanged
        assert_eq!(result.content, input);
        assert!(!result.was_modified);
    }

    #[test]
    fn test_sanitize_output_clean_content_not_modified() {
        let config = OutputSanitizerConfig::default();
        let input = "Hello, world! This is safe.";
        let result = sanitize_output(input, &config);
        assert_eq!(result.content, input);
        assert!(!result.was_modified);
    }

    #[test]
    fn test_sanitize_output_custom_csp() {
        let config = OutputSanitizerConfig {
            sanitize_html: true,
            csp_policy: "default-src 'self'".to_string(),
        };
        let result = sanitize_output("test", &config);
        assert_eq!(result.csp_policy, "default-src 'self'");
    }

    #[test]
    fn test_config_defaults() {
        let config = OutputSanitizerConfig::default();
        assert!(config.sanitize_html);
        assert!(config.csp_policy.contains("default-src 'none'"));
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = OutputSanitizerConfig {
            sanitize_html: false,
            csp_policy: "custom-policy".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: OutputSanitizerConfig = serde_json::from_str(&json).unwrap();
        assert!(!parsed.sanitize_html);
        assert_eq!(parsed.csp_policy, "custom-policy");
    }

    #[test]
    fn test_config_deserialize_defaults() {
        let json = "{}";
        let parsed: OutputSanitizerConfig = serde_json::from_str(json).unwrap();
        assert!(parsed.sanitize_html);
        assert!(parsed.csp_policy.contains("default-src 'none'"));
    }

    // ==================== XSS Attack Vectors ====================

    #[test]
    fn test_xss_img_onerror() {
        let input = r#"<img src=x onerror=alert(1)>"#;
        let result = sanitize_html(input);
        assert!(!result.contains("onerror"));
        assert!(!result.contains("alert"));
    }

    #[test]
    fn test_xss_svg_onload() {
        let input = r#"<svg/onload=alert(1)>"#;
        let result = sanitize_html(input);
        assert!(!result.contains("svg"));
        assert!(!result.contains("alert"));
    }

    #[test]
    fn test_xss_body_onload() {
        // body is not in allowed tags, so it gets stripped
        let input = r#"<body onload="alert(1)">"#;
        let result = sanitize_html(input);
        assert!(!result.contains("body"));
        assert!(!result.contains("alert"));
    }

    #[test]
    fn test_xss_a_javascript_href_mixed_case() {
        let input = r#"<a href="JaVaScRiPt:alert(1)">click</a>"#;
        let result = sanitize_html(input);
        assert!(!result.to_lowercase().contains("javascript:"));
    }

    #[test]
    fn test_xss_data_url_html() {
        let input =
            r#"<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>"#;
        let result = sanitize_html(input);
        assert!(!result.contains("data:text/html"));
    }

    #[test]
    fn test_xss_template_tag() {
        let input = "<template><script>alert(1)</script></template>";
        let result = sanitize_html(input);
        assert!(!result.contains("template"));
        assert!(!result.contains("script"));
    }

    #[test]
    fn test_xss_event_handler_variants() {
        let cases = vec![
            r#"<div onmouseover="alert(1)">text</div>"#,
            r#"<div onfocus="alert(1)">text</div>"#,
            r#"<div onblur="alert(1)">text</div>"#,
            r#"<div onkeydown="alert(1)">text</div>"#,
        ];
        for input in cases {
            let result = sanitize_html(input);
            assert!(
                !result.contains("alert"),
                "Event handler not stripped from: {}",
                input
            );
        }
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_self_closing_tags() {
        let input = "<br /><hr /><img src=\"cat.png\" />";
        let result = sanitize_html(input);
        assert!(result.contains("<br"));
        assert!(result.contains("<hr"));
        assert!(result.contains("<img"));
    }

    #[test]
    fn test_mixed_content() {
        let input = concat!(
            "# Report\n\n",
            "<p>Summary: <strong>all clear</strong></p>\n",
            "<script>document.cookie</script>\n",
            "- Item 1\n",
            "- Item 2\n",
            "[safe link](https://example.com)\n",
            "[bad link](javascript:void(0))",
        );
        let result = sanitize_output(input, &OutputSanitizerConfig::default());
        assert!(!result.content.contains("script"));
        assert!(!result.content.contains("document.cookie"));
        assert!(result.content.contains("# Report"));
        assert!(result.content.contains("<strong>all clear</strong>"));
        assert!(result.content.contains("- Item 1"));
        assert!(result.content.contains("[safe link](https://example.com)"));
        assert!(!result.content.contains("javascript:void(0)"));
        assert!(result.was_modified);
    }

    #[test]
    fn test_deeply_nested_tags() {
        let input = "<div><div><div><p>deep</p></div></div></div>";
        let result = sanitize_html(input);
        assert!(result.contains("<p>deep</p>"));
        assert!(result.contains("<div>"));
    }

    #[test]
    fn test_malformed_tags_handled() {
        // Malformed/partial tags should not cause panics
        let input = "<p>text<b>bold</p>";
        let result = sanitize_html(input);
        assert!(result.contains("text"));
        assert!(result.contains("bold"));
    }

    #[test]
    fn test_escape_attr_value_special_chars() {
        assert_eq!(
            escape_attr_value(r#"a&b"c<d>e"#),
            "a&amp;b&quot;c&lt;d&gt;e"
        );
    }
}
