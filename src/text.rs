/// Truncate to at most `max` characters, appending "…" when cut.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

/// Remove HTML tags, decode a few common entities and collapse whitespace.
pub fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => {
                in_tag = true;
                out.push(' ');
            }
            '>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let decoded = out
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&amp;", "&");
    collapse_ws(&decoded)
}

pub fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Case-insensitive match of `needle` in `haystack` at word boundaries.
/// Both arguments are expected to be lowercase already.
pub fn contains_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack
        .match_indices(needle)
        .any(|(idx, _)| is_word_at(haystack, idx, needle.len()))
}

/// Blank out every whole-word occurrence of each of `terms` in `haystack`, so that
/// `contains_word` no longer finds words that are only part of them. Matched bytes
/// become spaces, which are word boundaries. Both arguments are expected to be
/// lowercase already; empty terms are skipped.
/// Every term is matched against the original text, and overlapping occurrences
/// are found too, so overlapping terms (`ingress`, `ingress-nginx`) give the same
/// result in any order.
pub fn mask_words(haystack: &str, terms: &[String]) -> String {
    let mut ranges = Vec::new();
    for term in terms.iter().filter(|t| !t.is_empty()) {
        let mut from = 0;
        while let Some(pos) = haystack[from..].find(term.as_str()) {
            let idx = from + pos;
            if is_word_at(haystack, idx, term.len()) {
                ranges.push((idx, idx + term.len()));
            }
            // Next char boundary, so overlapping occurrences are not skipped.
            from = idx + haystack[idx..].chars().next().map_or(1, char::len_utf8);
        }
    }
    let mut out = haystack.to_string();
    for (start, end) in ranges {
        out.replace_range(start..end, &" ".repeat(end - start));
    }
    out
}

/// True when `haystack[idx..idx + len]` is not preceded or followed by an alphanumeric char.
fn is_word_at(haystack: &str, idx: usize, len: usize) -> bool {
    let before_ok = haystack[..idx]
        .chars()
        .next_back()
        .is_none_or(|c| !c.is_alphanumeric());
    let after_ok = haystack[idx + len..]
        .chars()
        .next()
        .is_none_or(|c| !c.is_alphanumeric());
    before_ok && after_ok
}

/// Escape characters that would be interpreted as Discord markdown.
pub fn escape_md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '*' | '_' | '~' | '`' | '|' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            // Square brackets break masked links.
            '[' => out.push('('),
            ']' => out.push(')'),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_counts_chars() {
        assert_eq!(truncate("あいうえお", 10), "あいうえお");
        assert_eq!(truncate("あいうえお", 3), "あい…");
        assert_eq!(truncate("abc", 0), "");
    }

    #[test]
    fn strips_html() {
        assert_eq!(
            strip_html("<p>Hello&nbsp;<b>world</b> &amp; more</p>\n\n<br/>x"),
            "Hello world & more x"
        );
    }

    #[test]
    fn word_boundaries() {
        assert!(contains_word("nginx 1.27 vulnerability", "nginx"));
        assert!(contains_word("a flaw in openssh-server", "openssh"));
        assert!(contains_word("the linux kernel: fix", "linux kernel"));
        assert!(!contains_word("libnginxfoo", "nginx"));
        assert!(!contains_word("sudoers", "sudo"));
        assert!(contains_word("x sudo", "sudo"));
        assert!(contains_word("中文 nginx", "nginx"));
        assert!(!contains_word("anything", ""));
    }

    #[test]
    fn masks_whole_words_only() {
        let terms = vec!["ingress-nginx".to_string(), "nginx ui".to_string()];
        let masked = mask_words("kubernetes ingress-nginx", &terms);
        assert!(!contains_word(&masked, "nginx"), "{masked}");
        assert!(contains_word(&masked, "kubernetes"));
        // A real `nginx` next to an excluded term survives.
        let masked = mask_words("nginx and ingress-nginx", &terms);
        assert!(contains_word(&masked, "nginx"), "{masked}");
        let masked = mask_words("nginx ui: xss in nginx uis", &terms);
        assert!(contains_word(&masked, "nginx"), "{masked}");
        assert!(!contains_word(&masked, "ui"), "{masked}");
        // Not a whole word: left alone.
        assert_eq!(mask_words("myingress-nginx", &terms), "myingress-nginx");
        assert_eq!(mask_words("中文 nginx ui", &terms), "中文         ");
        assert_eq!(mask_words("abc", &[String::new()]), "abc");
        // Overlapping occurrences of the same term.
        let terms = vec!["nginx-nginx".to_string()];
        let masked = mask_words("nginx-nginx-nginx", &terms);
        assert!(!contains_word(&masked, "nginx"), "{masked}");
        // Overlapping terms: the result does not depend on their order.
        for terms in [["ingress", "ingress-nginx"], ["ingress-nginx", "ingress"]] {
            let terms: Vec<String> = terms.iter().map(|t| t.to_string()).collect();
            let masked = mask_words("kubernetes ingress-nginx", &terms);
            assert!(!contains_word(&masked, "nginx"), "{terms:?}: {masked}");
        }
    }

    #[test]
    fn escapes_markdown() {
        assert_eq!(escape_md("a*b_[c]"), "a\\*b\\_(c)");
    }
}
