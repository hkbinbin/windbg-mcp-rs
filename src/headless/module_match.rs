pub(crate) fn module_selector_matches(selector: &str, candidate: &str) -> bool {
    let selector = normalize_module_pattern(selector);
    if selector.is_empty() {
        return false;
    }
    wildcard_match(&selector, &normalize_module_name(candidate))
}

pub(crate) fn normalize_module_name(value: &str) -> String {
    normalize_module_like(value, false)
}

fn normalize_module_pattern(value: &str) -> String {
    normalize_module_like(value, true)
}

fn normalize_module_like(value: &str, keep_wildcards: bool) -> String {
    let mut normalized = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    if let Some(last) = normalized.rsplit(['\\', '/']).next() {
        normalized = last.to_string();
    }
    if !keep_wildcards && let Some(last) = normalized.rsplit(':').next() {
        normalized = last.to_string();
    }
    if let Some((stem, extension)) = normalized.rsplit_once('.')
        && matches!(extension, "sys" | "dll" | "exe")
    {
        normalized = stem.to_string();
    }
    normalized
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    wildcard_match_bytes(pattern.as_bytes(), value.as_bytes())
}

fn wildcard_match_bytes(pattern: &[u8], value: &[u8]) -> bool {
    match pattern.split_first() {
        None => value.is_empty(),
        Some((&b'*', rest)) => {
            wildcard_match_bytes(rest, value)
                || (!value.is_empty() && wildcard_match_bytes(pattern, &value[1..]))
        }
        Some((&b'?', rest)) => !value.is_empty() && wildcard_match_bytes(rest, &value[1..]),
        Some((&head, rest)) => {
            !value.is_empty() && head == value[0] && wildcard_match_bytes(rest, &value[1..])
        }
    }
}
