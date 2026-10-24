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
    for (idx, _) in haystack.match_indices(needle) {
        let before_ok = haystack[..idx]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after_ok = haystack[idx + needle.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
    }
    false
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
    fn escapes_markdown() {
        assert_eq!(escape_md("a*b_[c]"), "a\\*b\\_(c)");
    }
}
