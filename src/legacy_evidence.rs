use regex::Regex;
use std::{collections::HashMap, sync::LazyLock};

static TEXT: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    include_str!("legacy_evidence.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect()
});

struct EvidencePattern {
    regex: Regex,
    english: Vec<&'static str>,
    nested: Vec<bool>,
}

// Keep stored evidence stable. Localize only the app's known message formats at display time.
static EVIDENCE_PATTERNS: LazyLock<Vec<EvidencePattern>> = LazyLock::new(|| {
    let Ok(placeholder) = Regex::new(r"\{[^{}]*\}") else {
        return Vec::new();
    };
    include_str!("legacy_evidence.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(thai, _)| placeholder.is_match(thai))
        .filter_map(|(thai, english)| {
            let parts = placeholder.split(thai).collect::<Vec<_>>();
            let english = placeholder.split(english).collect::<Vec<_>>();
            if parts.len() != english.len() || parts.iter().all(|part| part.is_empty()) {
                return None;
            }
            let pattern = parts
                .into_iter()
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join("(.+?)");
            Some(EvidencePattern {
                regex: Regex::new(&format!(r"(?s)\A{pattern}\z")).ok()?,
                english,
                nested: placeholder
                    .find_iter(thai)
                    .map(|field| {
                        matches!(
                            field.as_str(),
                            "{reason}" | "{detail}" | "{binding}" | "{fixed}"
                        )
                    })
                    .collect(),
            })
        })
        .collect()
});

pub fn evidence(text: &str) -> String {
    if !text.contains(|ch| ('ก'..='๙').contains(&ch)) {
        return text.into();
    }
    if let Some(translated) = TEXT.get(text) {
        return (*translated).into();
    }
    for pattern in EVIDENCE_PATTERNS.iter() {
        if let Some(captures) = pattern.regex.captures(text) {
            let mut translated = pattern.english[0].to_string();
            for ((capture, suffix), nested) in captures
                .iter()
                .skip(1)
                .zip(&pattern.english[1..])
                .zip(&pattern.nested)
            {
                if let Some(value) = capture {
                    if *nested {
                        translated.push_str(&evidence(value.as_str()));
                    } else {
                        translated.push_str(value.as_str());
                    }
                }
                translated.push_str(suffix);
            }
            return translated;
        }
    }
    if text.contains(" · ") {
        return text
            .split(" · ")
            .map(evidence)
            .collect::<Vec<_>>()
            .join(" · ");
    }
    text.into()
}
