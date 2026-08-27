//! Browser automation tools — inspired by openocta's `browser` package.
//!
//! Enables the AI agent to:
//!
//! - **Fetch a URL** and extract its text content (for reading docs, wikis,
//!   Stack Overflow answers, Kubernetes changelogs, etc.)
//! - **Search the web** for solutions to cluster problems.
//! - **Extract structured data** from web pages (JSON-LD, tables, etc.)
//!
//! These are read-only tools — the agent can browse but not interact with
//! web forms or perform actions on websites.
//!
//! Implementation: uses `reqwest` (already in deps) to fetch pages, then
//! a simple HTML-to-text extractor for readable content.

use serde::Serialize;

/// Fetch a URL and return its text content.
pub async fn fetch_url(url: &str, max_chars: usize) -> Result<UrlContent, String> {
    let client = k7s_deps::reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("k7s-ai/1.0")
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetch failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body = resp.text().await.map_err(|e| e.to_string())?;

    // If it's HTML, extract text content.
    let text = if content_type.contains("text/html") {
        html_to_text(&body, max_chars)
    } else {
        body.chars().take(max_chars).collect()
    };

    Ok(UrlContent {
        url: url.to_string(),
        content_type,
        text,
        fetched_at: k7s_deps::chrono::Utc::now().to_rfc3339(),
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlContent {
    pub url: String,
    pub content_type: String,
    pub text: String,
    pub fetched_at: String,
}

/// Simple HTML-to-text extraction. Strips tags, scripts, styles, and collapses
/// whitespace. Not a full DOM parser — good enough for extracting readable
/// content from docs and Stack Overflow.
fn html_to_text(html: &str, max_chars: usize) -> String {
    let mut result = String::new();
    let mut skip_content = false; // inside <script> or <style>
    let mut tag_name = String::new();

    let chars: Vec<char> = html.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if result.chars().count() >= max_chars {
            break;
        }
        let c = chars[i];
        if c == '<' {
            // Extract tag name; note whether this is a closing tag. The old
            // code stripped the '/' before collecting the name, so `</script>`
            // matched the "script" arm and RE-ENABLED skipping — everything
            // after the first script open tag was dropped, and the
            // `"/script"` arm was unreachable dead code.
            let mut closing = false;
            tag_name.clear();
            let mut j = i + 1;
            if j < chars.len() && chars[j] == '/' {
                closing = true;
                j += 1;
            }
            while j < chars.len() && chars[j].is_ascii_alphabetic() {
                tag_name.push(chars[j].to_ascii_lowercase());
                j += 1;
            }
            // Toggle script/style skipping.
            match tag_name.as_str() {
                "script" | "style" => skip_content = !closing,
                _ => {}
            }
            // Advance to the closing '>'.
            while i < chars.len() && chars[i] != '>' {
                i += 1;
            }
            if i < chars.len() {
                i += 1; // skip '>'
            }
            if !skip_content {
                result.push(' ');
            }

            continue;
        }
        if !skip_content {
            result.push(c);
        }
        i += 1;
    }

    // Collapse whitespace.
    let mut collapsed = String::new();
    let mut last_was_space = false;
    for c in result.chars() {
        if c.is_whitespace() {
            if !last_was_space {
                collapsed.push(' ');
            }
            last_was_space = true;
        } else {
            collapsed.push(c);
            last_was_space = false;
        }
    }

    collapsed.trim().to_string()
}

/// Search the web using a simple search API (DuckDuckGo Instant Answers).
/// Returns a summary if available, otherwise a list of result URLs.
pub async fn web_search(query: &str) -> Result<SearchResult, String> {
    let client = k7s_deps::reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("k7s-ai/1.0")
        .build()
        .map_err(|e| e.to_string())?;

    // DuckDuckGo Instant Answer API (no API key needed).
    let url = format!(
        "https://api.duckduckgo.com/?q={}&format=json&no_html=1&skip_disambig=1",
        k7s_deps::urlencoding::encode(query)
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("search failed: {e}"))?;

    let body: k7s_deps::serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;

    let abstract_text = body
        .get("AbstractText")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let abstract_url = body
        .get("AbstractURL")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let results: Vec<String> = body
        .get("RelatedTopics")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    t.get("FirstURL")
                        .and_then(|u| u.as_str())
                        .map(|s| s.to_string())
                })
                .take(5)
                .collect()
        })
        .unwrap_or_default();

    Ok(SearchResult {
        query: query.to_string(),
        summary: abstract_text,
        source_url: abstract_url,
        related_urls: results,
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub query: String,
    pub summary: String,
    pub source_url: String,
    pub related_urls: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_to_text_strips_tags() {
        let html = "<html><body><h1>Title</h1><p>Hello <b>world</b></p><script>var x=1;</script></body></html>";
        let text = html_to_text(html, 1000);
        assert!(text.contains("Title"));
        assert!(text.contains("Hello world"));
        assert!(!text.contains("var x"));
        assert!(!text.contains("<"));
    }

    #[test]
    fn html_to_text_respects_max_chars() {
        let html = "<p>".to_string() + &"a".repeat(5000) + "</p>";
        let text = html_to_text(&html, 100);
        assert!(text.chars().count() <= 110); // some slack for whitespace collapse
    }

    /// Regression: `</script>` used to re-enable skipping instead of ending
    /// it, so everything after the first script tag was dropped — real pages
    /// (with an early analytics snippet) extracted to near-empty text.
    #[test]
    fn html_to_text_recovers_after_closed_script() {
        let html =
            "<html><head><script>var x=1;</script></head><body>正文内容 body text</body></html>";
        let text = html_to_text(html, 1000);
        assert!(text.contains("正文内容"));
        assert!(text.contains("body text"));
        assert!(!text.contains("var x"));
    }

    #[test]
    fn html_to_text_recovers_after_closed_style() {
        let html = "<style>a { color: red; }</style>visible text";
        let text = html_to_text(html, 1000);
        assert!(text.contains("visible text"));
        assert!(!text.contains("color"));
    }
}
