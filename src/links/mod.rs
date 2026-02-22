//! Link understanding pipeline
//!
//! Extracts URLs from message text, fetches their content with SSRF protection,
//! converts HTML to text, and caches results for efficient reuse.
//!
//! Features:
//! - URL extraction with code block awareness (skips URLs in backtick blocks)
//! - SSRF-protected fetching via [`MediaFetcher`](crate::media::MediaFetcher)
//! - HTML-to-text conversion with title and meta description extraction
//! - LRU cache with TTL-based expiration (default: 1 hour, 100 entries)
//!
//! # Example
//!
//! ```ignore
//! use carapace::links::{LinkUnderstanding, LinkConfig};
//!
//! let lu = LinkUnderstanding::new(LinkConfig::default());
//!
//! // Extract URLs from text
//! let urls = LinkUnderstanding::extract_urls("Check out https://example.com");
//! assert_eq!(urls, vec!["https://example.com"]);
//!
//! // Fetch and summarize a single URL
//! let summary = lu.fetch_and_summarize("https://example.com").await?;
//! println!("Title: {:?}", summary.title);
//!
//! // Process a full message (extract + fetch all URLs)
//! let summaries = lu.process_message("Visit https://example.com").await;
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use regex::Regex;
use thiserror::Error;

use crate::media::{FetchConfig, FetchError, MediaFetcher};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum response size for link fetching (512KB)
pub const DEFAULT_LINK_MAX_SIZE: u64 = 512 * 1024;

/// Default fetch timeout for link fetching (15 seconds)
pub const DEFAULT_LINK_TIMEOUT_MS: u64 = 15_000;

/// Default maximum number of cached entries
pub const DEFAULT_CACHE_MAX_ENTRIES: usize = 100;

/// Default cache TTL in seconds (1 hour)
pub const DEFAULT_CACHE_TTL_SECS: u64 = 3600;

/// Default text preview length (first ~2000 chars of extracted text)
pub const DEFAULT_TEXT_PREVIEW_LEN: usize = 2000;

/// Maximum number of URLs to process from a single message
pub const MAX_URLS_PER_MESSAGE: usize = 5;

static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+").expect("URL regex is valid")
});
static FENCED_CODE_BLOCK_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)```.*?```").expect("fenced code block regex"));
static INLINE_CODE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"`[^`]+`").expect("inline code regex"));
static TITLE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").expect("title regex"));
static META_DESCRIPTION_NAME_FIRST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)<meta\s+(?:[^>]*?\s)?name\s*=\s*["']description["'][^>]*?\scontent\s*=\s*["'](.*?)["'][^>]*/?\s*>"#,
    )
    .expect("meta description regex (name first)")
});
static META_DESCRIPTION_CONTENT_FIRST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)<meta\s+(?:[^>]*?\s)?content\s*=\s*["'](.*?)["'][^>]*?\sname\s*=\s*["']description["'][^>]*/?\s*>"#,
    )
    .expect("meta description regex (content first)")
});
static SCRIPT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<script[^>]*>.*?</script>").expect("script regex"));
static STYLE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<style[^>]*>.*?</style>").expect("style regex"));
static COMMENT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->").expect("comment regex"));
static BLOCK_TAG_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)</?(?:div|p|br|h[1-6]|li|tr|blockquote|hr|section|article|header|footer|nav|main|aside)[^>]*>")
        .expect("block tag regex")
});
static TAG_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").expect("tag regex"));
static MULTI_NEWLINE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\n\s*\n").expect("multi newline regex"));
static SPACES_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[^\S\n]+").expect("spaces regex"));

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during link understanding
#[derive(Error, Debug, Clone)]
pub enum LinkError {
    #[error("Fetch failed: {0}")]
    Fetch(#[from] FetchError),

    #[error("Content not text: {0}")]
    NotTextContent(String),

    #[error("UTF-8 decode error: {0}")]
    Utf8(String),
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the link understanding pipeline
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Maximum response size in bytes (default: 512KB)
    pub max_size: u64,

    /// Request timeout in milliseconds (default: 15s)
    pub timeout_ms: u64,

    /// Maximum number of cached link summaries (default: 100). Set to 0 to disable caching.
    pub cache_max_entries: usize,

    /// Cache TTL in seconds (default: 3600 = 1 hour)
    pub cache_ttl_secs: u64,

    /// Maximum length of the text preview (default: 2000 chars)
    pub text_preview_len: usize,

    /// Maximum URLs extracted and processed per message (default: 5)
    pub max_urls_per_message: usize,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_LINK_MAX_SIZE,
            timeout_ms: DEFAULT_LINK_TIMEOUT_MS,
            cache_max_entries: DEFAULT_CACHE_MAX_ENTRIES,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            text_preview_len: DEFAULT_TEXT_PREVIEW_LEN,
            max_urls_per_message: MAX_URLS_PER_MESSAGE,
        }
    }
}

// ---------------------------------------------------------------------------
// LinkSummary
// ---------------------------------------------------------------------------

/// Result of fetching and summarizing a URL's content
#[derive(Debug, Clone)]
pub struct LinkSummary {
    /// The original URL
    pub url: String,

    /// Page title extracted from `<title>` tag
    pub title: Option<String>,

    /// Meta description extracted from `<meta name="description">`
    pub description: Option<String>,

    /// First N characters of the extracted text content
    pub text_preview: String,

    /// Content-Type from the HTTP response
    pub content_type: String,

    /// Unix timestamp (seconds) when the content was fetched
    pub fetched_at: u64,
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// Internal LRU cache for link summaries.
#[derive(Debug)]
struct LinkCache {
    entries: Option<HashMap<String, LinkSummary>>,
    order: VecDeque<String>,
    ttl_secs: u64,
    max_entries: usize,
}

impl LinkCache {
    fn new(max_entries: usize, ttl_secs: u64) -> Self {
        // Disable cache entirely when max_entries is 0.
        let entries = if max_entries == 0 {
            None
        } else {
            Some(HashMap::new())
        };
        Self {
            entries,
            order: VecDeque::new(),
            ttl_secs,
            max_entries,
        }
    }

    /// Get a cached entry if it exists and has not expired.
    fn get(&mut self, url: &str) -> Option<LinkSummary> {
        let now = current_epoch_secs();
        let mut cached: Option<LinkSummary> = None;
        let mut expired = false;

        {
            let cache = self.entries.as_mut()?;
            if let Some(entry) = cache.get(url) {
                if now.saturating_sub(entry.fetched_at) < self.ttl_secs {
                    cached = Some(entry.clone());
                } else {
                    expired = true;
                }
            }
            if expired {
                cache.remove(url);
            }
        }

        if let Some(entry) = cached {
            self.touch(url);
            return Some(entry);
        }

        if expired {
            self.remove_from_order(url);
        }

        None
    }

    /// Insert a summary into the cache, evicting the oldest entry if at capacity.
    fn insert(&mut self, summary: LinkSummary) {
        let Some(cache) = self.entries.as_mut() else {
            return;
        };
        let key = summary.url.clone();
        let exists = cache.contains_key(&key);
        cache.insert(key.clone(), summary);
        if exists {
            self.touch(&key);
        } else {
            self.order.push_back(key);
            self.evict_if_needed();
        }
    }

    /// Return the current number of (non-evicted) entries.
    fn len(&self) -> usize {
        self.entries.as_ref().map(|cache| cache.len()).unwrap_or(0)
    }

    fn touch(&mut self, url: &str) {
        if let Some(pos) = self.order.iter().position(|k| k == url) {
            self.order.remove(pos);
        }
        self.order.push_back(url.to_string());
    }

    fn remove_from_order(&mut self, url: &str) {
        if let Some(pos) = self.order.iter().position(|k| k == url) {
            self.order.remove(pos);
        }
    }

    fn evict_if_needed(&mut self) {
        let Some(cache) = self.entries.as_mut() else {
            return;
        };
        while cache.len() > self.max_entries {
            if let Some(oldest) = self.order.pop_front() {
                cache.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LinkUnderstanding
// ---------------------------------------------------------------------------

/// Main interface for the link understanding pipeline.
///
/// Extracts URLs from text, fetches content with SSRF protection,
/// converts HTML to text, and caches results.
pub struct LinkUnderstanding {
    config: LinkConfig,
    fetcher: MediaFetcher,
    cache: Arc<Mutex<LinkCache>>,
}

impl LinkUnderstanding {
    /// Create a new `LinkUnderstanding` with the given configuration.
    pub fn new(config: LinkConfig) -> Self {
        let fetch_config = FetchConfig::default()
            .with_max_size(config.max_size)
            .with_timeout_ms(config.timeout_ms);

        let cache = LinkCache::new(config.cache_max_entries, config.cache_ttl_secs);

        Self {
            config,
            fetcher: MediaFetcher::with_config(fetch_config),
            cache: Arc::new(Mutex::new(cache)),
        }
    }

    /// Extract URLs from message text.
    ///
    /// Matches `http://` and `https://` URLs while skipping any URLs that
    /// appear inside backtick-delimited code spans or fenced code blocks.
    pub fn extract_urls(text: &str) -> Vec<String> {
        // First, blank out content inside code blocks so URLs within them are ignored.
        let cleaned = remove_code_blocks(text);

        let mut urls: Vec<String> = Vec::new();
        for mat in URL_REGEX.find_iter(&cleaned) {
            let url = mat.as_str().to_string();
            // Strip trailing punctuation that is likely sentence-ending, not part of the URL
            let url = strip_trailing_punctuation(&url);
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
        urls
    }

    /// Fetch a URL and produce a [`LinkSummary`].
    ///
    /// Returns a cached result if one exists and has not expired.
    pub async fn fetch_and_summarize(&self, url: &str) -> Result<LinkSummary, LinkError> {
        // Check cache first
        {
            let mut cache = self.cache.lock();
            if let Some(summary) = cache.get(url) {
                tracing::debug!(url = %url, "link cache hit");
                return Ok(summary);
            }
        }

        tracing::debug!(url = %url, "fetching link content");

        let result = self.fetcher.fetch(url).await?;

        let content_type = result
            .content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string());

        // Only process text-like content types
        if !is_text_content(&content_type) {
            return Err(LinkError::NotTextContent(content_type));
        }

        let body = String::from_utf8(result.bytes).map_err(|e| LinkError::Utf8(e.to_string()))?;

        let (title, description, text) = if content_type.contains("html") {
            let title = extract_title(&body);
            let description = extract_meta_description(&body);
            let text = html_to_text(&body);
            (title, description, text)
        } else {
            // Plain text or similar — use body directly
            (None, None, body)
        };

        let text_preview = truncate_preview(&text, self.config.text_preview_len);

        let summary = LinkSummary {
            url: url.to_string(),
            title,
            description,
            text_preview,
            content_type,
            fetched_at: current_epoch_secs(),
        };

        // Store in cache
        {
            let mut cache = self.cache.lock();
            cache.insert(summary.clone());
        }

        Ok(summary)
    }

    /// Extract URLs from the message and fetch summaries for each.
    ///
    /// Limits the number of URLs processed per message to
    /// [`LinkConfig::max_urls_per_message`]. Errors for individual URLs are
    /// logged and skipped — the returned vec contains only successful results.
    pub async fn process_message(&self, text: &str) -> Vec<LinkSummary> {
        let urls = Self::extract_urls(text);
        let mut summaries = Vec::new();

        for url in urls.iter().take(self.config.max_urls_per_message) {
            match self.fetch_and_summarize(url).await {
                Ok(summary) => summaries.push(summary),
                Err(e) => {
                    tracing::warn!(url = %url, error = %e, "failed to fetch link");
                }
            }
        }

        summaries
    }

    /// Return the number of entries currently in the cache.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().len()
    }
}

// ---------------------------------------------------------------------------
// HTML processing helpers
// ---------------------------------------------------------------------------

/// Remove fenced code blocks (```) and inline code spans (`` ` ``) from text,
/// replacing their content with spaces so URL positions are preserved.
fn remove_code_blocks(text: &str) -> String {
    let mut result = text.to_string();

    // Fenced code blocks: ```...```
    result = FENCED_CODE_BLOCK_REGEX
        .replace_all(&result, |m: &regex::Captures| " ".repeat(m[0].len()))
        .into_owned();

    // Inline code spans: `...`
    result = INLINE_CODE_REGEX
        .replace_all(&result, |m: &regex::Captures| " ".repeat(m[0].len()))
        .into_owned();

    result
}

/// Strip trailing punctuation characters that are likely part of the
/// surrounding sentence rather than the URL itself.
fn strip_trailing_punctuation(url: &str) -> String {
    let mut s = url.to_string();
    while s.ends_with('.') || s.ends_with(',') || s.ends_with(';') || s.ends_with(')') {
        s.pop();
    }
    s
}

/// Extract the page title from the `<title>` tag.
pub fn extract_title(html: &str) -> Option<String> {
    TITLE_REGEX
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| collapse_whitespace(&decode_html_entities(m.as_str())))
        .filter(|s| !s.is_empty())
}

/// Extract the meta description from `<meta name="description" content="...">`.
pub fn extract_meta_description(html: &str) -> Option<String> {
    // Handles both name="description" content="..." and content="..." name="description"
    if let Some(caps) = META_DESCRIPTION_NAME_FIRST_REGEX.captures(html) {
        let desc = collapse_whitespace(&decode_html_entities(caps.get(1).unwrap().as_str()));
        if !desc.is_empty() {
            return Some(desc);
        }
    }

    // Try reversed attribute order: content first, name second
    META_DESCRIPTION_CONTENT_FIRST_REGEX
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| collapse_whitespace(&decode_html_entities(m.as_str())))
        .filter(|s| !s.is_empty())
}

/// Convert HTML to plain text by stripping tags and collapsing whitespace.
pub fn html_to_text(html: &str) -> String {
    let mut text = html.to_string();

    // Remove <script> and <style> blocks entirely
    text = SCRIPT_REGEX.replace_all(&text, " ").into_owned();

    text = STYLE_REGEX.replace_all(&text, " ").into_owned();

    // Remove HTML comments
    text = COMMENT_REGEX.replace_all(&text, " ").into_owned();

    // Replace block-level tags with newlines for readability
    text = BLOCK_TAG_REGEX.replace_all(&text, "\n").into_owned();

    // Strip all remaining HTML tags
    text = TAG_REGEX.replace_all(&text, "").into_owned();

    // Decode HTML entities
    text = decode_html_entities(&text);

    // Collapse whitespace: multiple spaces/tabs -> single space, multiple newlines -> double
    collapse_whitespace(&text)
}

/// Decode common HTML entities.
fn decode_html_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
}

/// Collapse runs of whitespace into single spaces / double newlines.
fn collapse_whitespace(text: &str) -> String {
    // Replace multiple blank lines with a single blank line
    let collapsed = MULTI_NEWLINE_REGEX.replace_all(text, "\n\n").into_owned();

    // Replace runs of spaces/tabs (not newlines) with a single space
    let collapsed = SPACES_REGEX.replace_all(&collapsed, " ").into_owned();

    collapsed.trim().to_string()
}

/// Truncate text to approximately `max_len` bytes, breaking at a word boundary.
///
/// Uses `is_char_boundary()` to find a safe truncation point so that slicing
/// never panics on multi-byte UTF-8 characters.
fn truncate_preview(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        return text.to_string();
    }

    // Walk backward from max_len to find a char boundary
    let mut end = max_len;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    // Find the last space before `end` to avoid cutting mid-word
    let truncated = &text[..end];
    if let Some(last_space) = truncated.rfind(' ') {
        if last_space > end / 2 {
            return format!("{}...", &text[..last_space]);
        }
    }
    format!("{}...", truncated)
}

/// Check whether a Content-Type header value indicates text content.
fn is_text_content(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.contains("text/")
        || ct.contains("application/json")
        || ct.contains("application/xml")
        || ct.contains("application/xhtml")
        || ct.contains("application/javascript")
}

/// Current time as seconds since Unix epoch.
fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- URL extraction ---------------------------------------------------

    #[test]
    fn test_extract_simple_https_url() {
        let urls = LinkUnderstanding::extract_urls("Check out https://example.com for more info");
        assert_eq!(urls, vec!["https://example.com"]);
    }

    #[test]
    fn test_extract_http_url() {
        let urls = LinkUnderstanding::extract_urls("Visit http://example.org/path?q=1");
        assert_eq!(urls, vec!["http://example.org/path?q=1"]);
    }

    #[test]
    fn test_extract_multiple_urls() {
        let text = "See https://a.com and also https://b.com/page for details";
        let urls = LinkUnderstanding::extract_urls(text);
        assert_eq!(urls, vec!["https://a.com", "https://b.com/page"]);
    }

    #[test]
    fn test_extract_url_with_fragment() {
        let urls = LinkUnderstanding::extract_urls("https://example.com/page#section");
        assert_eq!(urls, vec!["https://example.com/page#section"]);
    }

    #[test]
    fn test_extract_url_with_query_params() {
        let urls = LinkUnderstanding::extract_urls("https://example.com/search?q=rust&lang=en");
        assert_eq!(urls, vec!["https://example.com/search?q=rust&lang=en"]);
    }

    #[test]
    fn test_extract_url_with_port() {
        let urls = LinkUnderstanding::extract_urls("http://localhost:8080/api");
        assert_eq!(urls, vec!["http://localhost:8080/api"]);
    }

    #[test]
    fn test_extract_deduplicates() {
        let text = "https://example.com is great. I love https://example.com";
        let urls = LinkUnderstanding::extract_urls(text);
        assert_eq!(urls, vec!["https://example.com"]);
    }

    #[test]
    fn test_extract_strips_trailing_period() {
        let urls = LinkUnderstanding::extract_urls("Visit https://example.com.");
        assert_eq!(urls, vec!["https://example.com"]);
    }

    #[test]
    fn test_extract_strips_trailing_comma() {
        let urls = LinkUnderstanding::extract_urls("See https://example.com, which is good");
        assert_eq!(urls, vec!["https://example.com"]);
    }

    #[test]
    fn test_extract_strips_trailing_paren() {
        let urls = LinkUnderstanding::extract_urls("(see https://example.com)");
        assert_eq!(urls, vec!["https://example.com"]);
    }

    #[test]
    fn test_extract_no_urls() {
        let urls = LinkUnderstanding::extract_urls("No links here, just text.");
        assert!(urls.is_empty());
    }

    #[test]
    fn test_extract_skips_inline_code() {
        let urls =
            LinkUnderstanding::extract_urls("Use `https://internal.api/secret` for the endpoint");
        assert!(urls.is_empty());
    }

    #[test]
    fn test_extract_skips_fenced_code_block() {
        let text = "Example:\n```\nhttps://example.com/in-code\n```\nBut visit https://real.com";
        let urls = LinkUnderstanding::extract_urls(text);
        assert_eq!(urls, vec!["https://real.com"]);
    }

    #[test]
    fn test_extract_skips_code_but_keeps_outside() {
        let text = "See https://outside.com and `https://inside.com` and https://also-outside.com";
        let urls = LinkUnderstanding::extract_urls(text);
        assert_eq!(
            urls,
            vec!["https://outside.com", "https://also-outside.com"]
        );
    }

    #[test]
    fn test_extract_complex_url() {
        let urls = LinkUnderstanding::extract_urls(
            "https://example.com/path/to/page?key=value&other=123#anchor",
        );
        assert_eq!(
            urls,
            vec!["https://example.com/path/to/page?key=value&other=123#anchor"]
        );
    }

    // -- Code block removal -----------------------------------------------

    #[test]
    fn test_remove_code_blocks_fenced() {
        let text = "before ```code here``` after";
        let cleaned = remove_code_blocks(text);
        assert!(!cleaned.contains("code here"));
        assert!(cleaned.contains("before"));
        assert!(cleaned.contains("after"));
    }

    #[test]
    fn test_remove_code_blocks_inline() {
        let text = "before `inline code` after";
        let cleaned = remove_code_blocks(text);
        assert!(!cleaned.contains("inline code"));
        assert!(cleaned.contains("before"));
        assert!(cleaned.contains("after"));
    }

    // -- HTML to text conversion ------------------------------------------

    #[test]
    fn test_html_to_text_simple() {
        let html = "<p>Hello <b>world</b></p>";
        let text = html_to_text(html);
        assert!(text.contains("Hello"));
        assert!(text.contains("world"));
        assert!(!text.contains("<p>"));
        assert!(!text.contains("<b>"));
    }

    #[test]
    fn test_html_to_text_removes_script() {
        let html = "<p>Visible</p><script>var x = 1;</script><p>Also visible</p>";
        let text = html_to_text(html);
        assert!(text.contains("Visible"));
        assert!(text.contains("Also visible"));
        assert!(!text.contains("var x"));
    }

    #[test]
    fn test_html_to_text_removes_style() {
        let html = "<style>body { color: red; }</style><p>Content</p>";
        let text = html_to_text(html);
        assert!(text.contains("Content"));
        assert!(!text.contains("color: red"));
    }

    #[test]
    fn test_html_to_text_removes_comments() {
        let html = "<!-- comment --><p>Visible</p>";
        let text = html_to_text(html);
        assert!(text.contains("Visible"));
        assert!(!text.contains("comment"));
    }

    #[test]
    fn test_html_to_text_decodes_entities() {
        let html = "<p>A &amp; B &lt; C &gt; D &quot;E&quot;</p>";
        let text = html_to_text(html);
        assert!(text.contains("A & B < C > D \"E\""));
    }

    #[test]
    fn test_html_to_text_collapses_whitespace() {
        let html = "<p>  Hello    world  </p>";
        let text = html_to_text(html);
        assert_eq!(text, "Hello world");
    }

    #[test]
    fn test_html_to_text_full_page() {
        let html = r#"<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
<h1>Welcome</h1>
<p>This is a paragraph.</p>
<script>alert('x');</script>
<style>.foo { display: none; }</style>
<!-- hidden -->
<p>Another paragraph with &amp; entities.</p>
</body>
</html>"#;
        let text = html_to_text(html);
        assert!(text.contains("Welcome"));
        assert!(text.contains("This is a paragraph."));
        assert!(text.contains("Another paragraph with & entities."));
        assert!(!text.contains("alert"));
        assert!(!text.contains("display: none"));
        assert!(!text.contains("hidden"));
    }

    // -- Title extraction -------------------------------------------------

    #[test]
    fn test_extract_title_basic() {
        let html = "<html><head><title>My Page</title></head></html>";
        assert_eq!(extract_title(html), Some("My Page".to_string()));
    }

    #[test]
    fn test_extract_title_with_whitespace() {
        let html = "<title>  My   Page  </title>";
        assert_eq!(extract_title(html), Some("My Page".to_string()));
    }

    #[test]
    fn test_extract_title_with_entities() {
        let html = "<title>A &amp; B</title>";
        assert_eq!(extract_title(html), Some("A & B".to_string()));
    }

    #[test]
    fn test_extract_title_missing() {
        let html = "<html><head></head><body>No title</body></html>";
        assert_eq!(extract_title(html), None);
    }

    #[test]
    fn test_extract_title_empty() {
        let html = "<title></title>";
        assert_eq!(extract_title(html), None);
    }

    #[test]
    fn test_extract_title_case_insensitive() {
        let html = "<TITLE>Upper Case</TITLE>";
        assert_eq!(extract_title(html), Some("Upper Case".to_string()));
    }

    // -- Meta description extraction --------------------------------------

    #[test]
    fn test_extract_meta_description_basic() {
        let html = r#"<meta name="description" content="A great page about Rust">"#;
        assert_eq!(
            extract_meta_description(html),
            Some("A great page about Rust".to_string())
        );
    }

    #[test]
    fn test_extract_meta_description_reversed_order() {
        let html = r#"<meta content="Reversed order" name="description">"#;
        assert_eq!(
            extract_meta_description(html),
            Some("Reversed order".to_string())
        );
    }

    #[test]
    fn test_extract_meta_description_self_closing() {
        let html = r#"<meta name="description" content="Self closing" />"#;
        assert_eq!(
            extract_meta_description(html),
            Some("Self closing".to_string())
        );
    }

    #[test]
    fn test_extract_meta_description_missing() {
        let html = r#"<meta name="viewport" content="width=device-width">"#;
        assert_eq!(extract_meta_description(html), None);
    }

    #[test]
    fn test_extract_meta_description_with_entities() {
        let html = r#"<meta name="description" content="A &amp; B">"#;
        assert_eq!(extract_meta_description(html), Some("A & B".to_string()));
    }

    #[test]
    fn test_extract_meta_description_case_insensitive() {
        let html = r#"<META NAME="description" CONTENT="Case insensitive">"#;
        assert_eq!(
            extract_meta_description(html),
            Some("Case insensitive".to_string())
        );
    }

    // -- Text preview truncation ------------------------------------------

    #[test]
    fn test_truncate_short_text() {
        let text = "Short text";
        assert_eq!(truncate_preview(text, 100), "Short text");
    }

    #[test]
    fn test_truncate_at_word_boundary() {
        let text = "Hello world this is a longer text that needs truncation";
        let preview = truncate_preview(text, 20);
        assert!(preview.ends_with("..."));
        assert!(preview.len() <= 25); // 20 chars + "..."
                                      // Should break at a word boundary
        assert!(preview.starts_with("Hello world this"));
    }

    #[test]
    fn test_truncate_exact_length() {
        let text = "ExactlyRight";
        assert_eq!(truncate_preview(text, 12), "ExactlyRight");
    }

    // -- Content type detection -------------------------------------------

    #[test]
    fn test_is_text_content_html() {
        assert!(is_text_content("text/html; charset=utf-8"));
    }

    #[test]
    fn test_is_text_content_plain() {
        assert!(is_text_content("text/plain"));
    }

    #[test]
    fn test_is_text_content_json() {
        assert!(is_text_content("application/json"));
    }

    #[test]
    fn test_is_text_content_xml() {
        assert!(is_text_content("application/xml"));
    }

    #[test]
    fn test_is_not_text_content_image() {
        assert!(!is_text_content("image/png"));
    }

    #[test]
    fn test_is_not_text_content_binary() {
        assert!(!is_text_content("application/octet-stream"));
    }

    // -- HTML entity decoding ---------------------------------------------

    #[test]
    fn test_decode_entities() {
        assert_eq!(decode_html_entities("&amp;"), "&");
        assert_eq!(decode_html_entities("&lt;"), "<");
        assert_eq!(decode_html_entities("&gt;"), ">");
        assert_eq!(decode_html_entities("&quot;"), "\"");
        assert_eq!(decode_html_entities("&#39;"), "'");
        assert_eq!(decode_html_entities("&apos;"), "'");
        assert_eq!(decode_html_entities("&nbsp;"), " ");
    }

    #[test]
    fn test_decode_entities_mixed() {
        assert_eq!(decode_html_entities("A &amp; B &lt; C"), "A & B < C");
    }

    // -- Trailing punctuation stripping -----------------------------------

    #[test]
    fn test_strip_trailing_period() {
        assert_eq!(
            strip_trailing_punctuation("https://example.com."),
            "https://example.com"
        );
    }

    #[test]
    fn test_strip_trailing_comma() {
        assert_eq!(
            strip_trailing_punctuation("https://example.com,"),
            "https://example.com"
        );
    }

    #[test]
    fn test_strip_trailing_paren() {
        assert_eq!(
            strip_trailing_punctuation("https://example.com)"),
            "https://example.com"
        );
    }

    #[test]
    fn test_strip_trailing_multiple() {
        assert_eq!(
            strip_trailing_punctuation("https://example.com)."),
            "https://example.com"
        );
    }

    #[test]
    fn test_strip_no_trailing() {
        assert_eq!(
            strip_trailing_punctuation("https://example.com/path"),
            "https://example.com/path"
        );
    }

    // -- Cache behavior ---------------------------------------------------

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = LinkCache::new(10, 3600);
        let summary = make_test_summary("https://example.com");
        cache.insert(summary.clone());

        let result = cache.get("https://example.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().url, "https://example.com");
    }

    #[test]
    fn test_cache_miss() {
        let mut cache = LinkCache::new(10, 3600);
        let result = cache.get("https://not-cached.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_eviction_at_capacity() {
        let mut cache = LinkCache::new(3, 3600);

        cache.insert(make_test_summary("https://a.com"));
        cache.insert(make_test_summary("https://b.com"));
        cache.insert(make_test_summary("https://c.com"));
        assert_eq!(cache.len(), 3);

        // Adding a 4th should evict the oldest (a.com)
        cache.insert(make_test_summary("https://d.com"));
        assert_eq!(cache.len(), 3);
        assert!(cache.get("https://a.com").is_none());
        assert!(cache.get("https://b.com").is_some());
        assert!(cache.get("https://c.com").is_some());
        assert!(cache.get("https://d.com").is_some());
    }

    #[test]
    fn test_cache_eviction_is_lru() {
        let mut cache = LinkCache::new(3, 3600);

        cache.insert(make_test_summary("https://a.com"));
        cache.insert(make_test_summary("https://b.com"));
        cache.insert(make_test_summary("https://c.com"));

        // Touch a.com so it becomes most recently used.
        assert!(cache.get("https://a.com").is_some());

        cache.insert(make_test_summary("https://d.com"));

        // b.com should be evicted (least recently used).
        assert!(cache.get("https://b.com").is_none());
        assert!(cache.get("https://a.com").is_some());
        assert!(cache.get("https://c.com").is_some());
        assert!(cache.get("https://d.com").is_some());
    }

    #[test]
    fn test_cache_ttl_expiration() {
        let mut cache = LinkCache::new(10, 3600);

        let mut summary = make_test_summary("https://expired.com");
        // Set fetched_at to 2 hours ago
        summary.fetched_at = current_epoch_secs() - 7200;
        cache.insert(summary);

        // Should be expired
        let result = cache.get("https://expired.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_ttl_still_valid() {
        let mut cache = LinkCache::new(10, 3600);

        let mut summary = make_test_summary("https://fresh.com");
        // Set fetched_at to 30 minutes ago
        summary.fetched_at = current_epoch_secs() - 1800;
        cache.insert(summary);

        // Should still be valid
        let result = cache.get("https://fresh.com");
        assert!(result.is_some());
    }

    #[test]
    fn test_cache_update_existing_entry() {
        let mut cache = LinkCache::new(10, 3600);

        let mut s1 = make_test_summary("https://example.com");
        s1.text_preview = "old content".to_string();
        cache.insert(s1);

        let mut s2 = make_test_summary("https://example.com");
        s2.text_preview = "new content".to_string();
        cache.insert(s2);

        assert_eq!(cache.len(), 1);
        let result = cache.get("https://example.com").unwrap();
        assert_eq!(result.text_preview, "new content");
    }

    #[test]
    fn test_cache_len() {
        let mut cache = LinkCache::new(10, 3600);
        assert_eq!(cache.len(), 0);

        cache.insert(make_test_summary("https://a.com"));
        assert_eq!(cache.len(), 1);

        cache.insert(make_test_summary("https://b.com"));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_disabled_when_zero() {
        let mut cache = LinkCache::new(0, 3600);
        cache.insert(make_test_summary("https://disabled.com"));
        assert_eq!(cache.len(), 0);
        assert!(cache.get("https://disabled.com").is_none());
    }

    // -- Config defaults --------------------------------------------------

    #[test]
    fn test_link_config_defaults() {
        let config = LinkConfig::default();
        assert_eq!(config.max_size, DEFAULT_LINK_MAX_SIZE);
        assert_eq!(config.timeout_ms, DEFAULT_LINK_TIMEOUT_MS);
        assert_eq!(config.cache_max_entries, DEFAULT_CACHE_MAX_ENTRIES);
        assert_eq!(config.cache_ttl_secs, DEFAULT_CACHE_TTL_SECS);
        assert_eq!(config.text_preview_len, DEFAULT_TEXT_PREVIEW_LEN);
        assert_eq!(config.max_urls_per_message, MAX_URLS_PER_MESSAGE);
    }

    // -- Helpers ----------------------------------------------------------

    fn make_test_summary(url: &str) -> LinkSummary {
        LinkSummary {
            url: url.to_string(),
            title: Some("Test Page".to_string()),
            description: Some("A test page".to_string()),
            text_preview: "Some preview text".to_string(),
            content_type: "text/html".to_string(),
            fetched_at: current_epoch_secs(),
        }
    }
}
