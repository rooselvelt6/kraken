use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::throttle::backoff_delay;
use crate::{FindingKind, OsintFinding, OsintSource, Reliability};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct SearchAggregator;

impl SearchAggregator {
    pub fn search(query: &str, sources: &[&str]) -> Vec<OsintFinding> {
        let mut all_results: Vec<SearchResult> = Vec::new();

        for source in sources {
            if *source == "web" {
                if let Ok(results) = Self::search_web(query) {
                    all_results.extend(results);
                }
            }
        }

        all_results = Self::deduplicate(all_results);
        all_results = Self::rank(all_results);

        all_results
            .into_iter()
            .map(|r| {
                let confidence = match r.source.as_str() {
                    "web" => 0.6,
                    _ => 0.5,
                };
                OsintFinding {
                    source: OsintSource {
                        name: format!("search/{}", r.source),
                        reliability: Reliability::Medium,
                        url: Some(r.url.clone()),
                    },
                    kind: FindingKind::Url,
                    value: r.url,
                    context: r.snippet,
                    confidence,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                }
            })
            .collect()
    }

    fn search_web(query: &str) -> Result<Vec<SearchResult>, String> {
        let url = format!(
            "https://html.duckduckgo.com/html/?q={}",
            url_encode(query)
        );
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| e.to_string())?;

        let mut last_error = String::new();
        for attempt in 0..3 {
            match client
                .get(&url)
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .send()
            {
                Ok(resp) => {
                    let body = resp.text().map_err(|e| format!("search response: {e}"))?;
                    return Self::parse_results(&body);
                }
                Err(e) => {
                    last_error = format!("search request failed: {e}");
                    if attempt < 2 {
                        std::thread::sleep(backoff_delay(attempt, 500));
                    }
                }
            }
        }
        Err(last_error)
    }

    fn parse_results(html: &str) -> Result<Vec<SearchResult>, String> {
        let document = scraper::Html::parse_document(html);
        let result_selector = scraper::Selector::parse(".result").map_err(|e| format!("result selector: {e}"))?;
        let link_selector = scraper::Selector::parse("a.result__a").map_err(|e| format!("link selector: {e}"))?;
        let snippet_selector = scraper::Selector::parse(".result__snippet").map_err(|e| format!("snippet selector: {e}"))?;

        let mut results = Vec::new();
        for result_elem in document.select(&result_selector) {
            let title = result_elem
                .select(&link_selector)
                .next()
                .map(|e| e.text().collect::<String>().trim().to_string())
                .unwrap_or_default();

            let url = result_elem
                .select(&link_selector)
                .next()
                .and_then(|e| e.value().attr("href"))
                .map(decode_redirect)
                .unwrap_or_default();

            let snippet = result_elem
                .select(&snippet_selector)
                .next()
                .map(|e| e.text().collect::<String>().trim().to_string());

            if !title.is_empty() && !url.is_empty() {
                results.push(SearchResult {
                    title,
                    url,
                    snippet,
                    source: "web".into(),
                });
            }
        }

        Ok(results)
    }

    fn deduplicate(results: Vec<SearchResult>) -> Vec<SearchResult> {
        let mut seen = std::collections::HashSet::new();
        results
            .into_iter()
            .filter(|r| seen.insert(r.url.clone()))
            .collect()
    }

    fn rank(mut results: Vec<SearchResult>) -> Vec<SearchResult> {
        results.sort_by(|a, b| {
            let a_rank = rank_score(a);
            let b_rank = rank_score(b);
            b_rank.partial_cmp(&a_rank).unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }
}

fn rank_score(result: &SearchResult) -> f64 {
    let mut score = 0.5;
    if !result.title.is_empty() {
        score += 0.1;
    }
    if result.snippet.is_some() {
        score += 0.1;
    }
    if result.url.starts_with("https://") {
        score += 0.1;
    }
    score
}

fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => result.push_str("%20"),
            _ => result.push_str(&format!("%{:02X}", byte)),
        }
    }
    result
}

fn decode_redirect(href: &str) -> String {
    if href.starts_with("//") {
        return format!("https:{}", href);
    }
    if let Some(pos) = href.find("uddg=") {
        let encoded = &href[pos + 5..];
        if let Some(amp) = encoded.find('&') {
            return percent_decode(&encoded[..amp]);
        }
        return percent_decode(encoded);
    }
    href.to_string()
}

fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deduplicate_removes_duplicates() {
        let results = vec![
            SearchResult {
                title: "A".into(),
                url: "https://example.com".into(),
                snippet: None,
                source: "web".into(),
            },
            SearchResult {
                title: "A (dup)".into(),
                url: "https://example.com".into(),
                snippet: None,
                source: "web".into(),
            },
        ];
        let deduped = SearchAggregator::deduplicate(results);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn rank_prioritizes_https_with_title_and_snippet() {
        let mut results = vec![
            SearchResult {
                title: "".into(),
                url: "http://a.com".into(),
                snippet: None,
                source: "web".into(),
            },
            SearchResult {
                title: "Best".into(),
                url: "https://b.com".into(),
                snippet: Some("desc".into()),
                source: "web".into(),
            },
        ];
        results = SearchAggregator::rank(results);
        assert!(results[0].url == "https://b.com");
    }

    #[test]
    fn percent_decode_works() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("foo%2Fbar"), "foo/bar");
    }

    #[test]
    fn url_encode_works() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a/b"), "a%2Fb");
    }

    #[test]
    fn decode_redirect_protocol_relative() {
        assert_eq!(decode_redirect("//example.com/path"), "https://example.com/path");
    }

    #[test]
    fn decode_redirect_uddg_param() {
        let href = "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&rut=abc";
        assert_eq!(decode_redirect(href), "https://example.com");
    }

    #[test]
    fn decode_redirect_no_transform() {
        assert_eq!(decode_redirect("https://example.com"), "https://example.com");
    }

    #[test]
    fn percent_decode_hex() {
        assert_eq!(percent_decode("%41%42%43"), "ABC");
    }

    #[test]
    fn percent_decode_empty() {
        assert_eq!(percent_decode(""), "");
    }

    #[test]
    fn percent_decode_invalid_hex() {
        assert_eq!(percent_decode("%ZZ"), "");
    }

    #[test]
    fn rank_score_https_bonus() {
        let r = SearchResult { title: "T".into(), url: "https://a.com".into(), snippet: None, source: "web".into() };
        let r2 = SearchResult { title: "T".into(), url: "http://a.com".into(), snippet: None, source: "web".into() };
        assert!(rank_score(&r) > rank_score(&r2));
    }

    #[test]
    fn rank_score_snippet_bonus() {
        let r = SearchResult { title: "T".into(), url: "https://a.com".into(), snippet: Some("desc".into()), source: "web".into() };
        let r2 = SearchResult { title: "T".into(), url: "https://a.com".into(), snippet: None, source: "web".into() };
        assert!(rank_score(&r) > rank_score(&r2));
    }

    #[test]
    fn rank_score_title_bonus() {
        let r = SearchResult { title: "Title".into(), url: "http://a.com".into(), snippet: None, source: "web".into() };
        let r2 = SearchResult { title: "".into(), url: "http://a.com".into(), snippet: None, source: "web".into() };
        assert!(rank_score(&r) > rank_score(&r2));
    }

    #[test]
    fn deduplicate_preserves_first() {
        let results = vec![
            SearchResult { title: "First".into(), url: "https://a.com".into(), snippet: None, source: "web".into() },
            SearchResult { title: "Second".into(), url: "https://a.com".into(), snippet: None, source: "web".into() },
        ];
        let deduped = SearchAggregator::deduplicate(results);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].title, "First");
    }

    #[test]
    fn rank_preserves_order_when_equal() {
        let mut results = vec![
            SearchResult { title: "A".into(), url: "http://a.com".into(), snippet: None, source: "web".into() },
            SearchResult { title: "B".into(), url: "http://b.com".into(), snippet: None, source: "web".into() },
        ];
        results = SearchAggregator::rank(results);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_result_struct() {
        let r = SearchResult { title: "Test".into(), url: "https://test.com".into(), snippet: Some("desc".into()), source: "web".into() };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("Test"));
    }
}
