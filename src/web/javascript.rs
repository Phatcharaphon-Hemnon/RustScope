use crate::domain::Outcome::{self, Finding, Insufficient, Passed};
use regex::Regex;
use semver::Version;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use url::Url;

pub(super) const RULE: &str = "X03-01";
const VERSION: &str = r"[0-9][0-9A-Za-z._+\-]*";
const VERSION_TOKEN: &str = "§§version§§";

static SNAPSHOT: LazyLock<Option<Vec<Library>>> = LazyLock::new(|| {
    let snapshot = include_str!("../../fixtures/advisories/retirejs.json");
    let libraries: BTreeMap<String, SourceLibrary> = serde_json::from_str(snapshot).ok()?;
    if libraries.is_empty() {
        return None;
    }
    libraries
        .into_iter()
        .map(|(name, source)| {
            let filename = source
                .extractors
                .filename
                .iter()
                .map(|pattern| {
                    let pattern = pattern
                        .trim_start_matches('/')
                        .replace(VERSION_TOKEN, &format!("{VERSION}?"));
                    Regex::new(&format!("^(?:{pattern})$"))
                })
                .collect::<Result<_, _>>()
                .ok()?;
            let uri = source
                .extractors
                .uri
                .iter()
                .map(|pattern| {
                    let suffix = if pattern.ends_with("(§§version§§)") {
                        "(?:/|$)"
                    } else if pattern.ends_with(".js") {
                        "$"
                    } else {
                        ""
                    };
                    // Leave optional filename suffixes outside the version capture. The optional
                    // slash in the markdown-it extractor needs a greedy capture before its `.*`.
                    let version = if pattern.contains(")/?.*") {
                        VERSION.to_owned()
                    } else {
                        format!("{VERSION}?")
                    };
                    Regex::new(&format!(
                        "{}{suffix}",
                        pattern.replace(VERSION_TOKEN, &version)
                    ))
                })
                .collect::<Result<_, _>>()
                .ok()?;
            Some(Library {
                name,
                filename,
                uri,
                vulnerabilities: source.vulnerabilities,
            })
        })
        .collect()
});

#[derive(Deserialize)]
struct SourceLibrary {
    extractors: Extractors,
    vulnerabilities: Vec<Advisory>,
}

#[derive(Deserialize)]
struct Extractors {
    #[serde(default)]
    filename: Vec<String>,
    #[serde(default)]
    uri: Vec<String>,
}

struct Library {
    name: String,
    filename: Vec<Regex>,
    uri: Vec<Regex>,
    vulnerabilities: Vec<Advisory>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Advisory {
    at_or_above: Option<String>,
    below: String,
    severity: String,
    identifiers: BTreeMap<String, Vec<String>>,
}

impl Advisory {
    fn affects(&self, version: &Version) -> Option<bool> {
        let lower = self.at_or_above.as_deref().map_or(Some(true), |bound| {
            Some(!version.cmp_precedence(&parse_bound(bound)?).is_lt())
        });
        let upper = parse_bound(&self.below).map(|bound| version.cmp_precedence(&bound).is_lt());
        match (lower, upper) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), Some(true)) => Some(true),
            _ => None,
        }
    }

    fn detail(&self) -> String {
        let ids = self
            .identifiers
            .iter()
            .flat_map(|(kind, ids)| {
                ids.iter().map(move |id| match kind.as_str() {
                    "CVE" | "githubID" => id.clone(),
                    _ => format!("{kind}:{id}"),
                })
            })
            .collect::<Vec<_>>()
            .join(", ");
        // Retire.js uses 999 upper bounds for open-ended or end-of-life ranges.
        let fixed = match self.below.as_str() {
            "999.0.0" | "999.999.999" | "1.999" | "2.999.999" | "3.999.999" => "Unspecified",
            below => below,
        };
        format!("{ids} ({}) · First fixed version: {fixed}", self.severity)
    }
}

fn parse_bound(value: &str) -> Option<Version> {
    // This legacy jQuery bound denotes the first 1.9.0 beta.
    let value = if value == "1.9.0b1" {
        "1.9.0-beta.1"
    } else {
        value
    };
    Version::parse(value)
        .ok()
        .or_else(|| match value.split('.').count() {
            1 => Version::parse(&format!("{value}.0.0")).ok(),
            2 => Version::parse(&format!("{value}.0")).ok(),
            _ => None,
        })
}

impl Library {
    fn assess(&self, declared: &str) -> (Outcome, String) {
        let Ok(version) = Version::parse(declared) else {
            return (
                Insufficient,
                "The declared version could not be compared using SemVer".into(),
            );
        };
        let mut findings = BTreeSet::new();
        let mut uncertain = false;
        for advisory in &self.vulnerabilities {
            match advisory.affects(&version) {
                Some(true) => {
                    findings.insert(advisory.detail());
                }
                Some(false) => {}
                None => uncertain = true,
            }
        }
        if !findings.is_empty() {
            let details = findings.into_iter().collect::<Vec<_>>().join(" | ");
            (Finding, format!("{declared} · {details}"))
        } else if uncertain {
            (
                Insufficient,
                format!(
                    "{declared} · An advisory has a range that could not be compared using SemVer"
                ),
            )
        } else {
            (
                Passed,
                format!("{declared} · Outside the affected range in Retire.js"),
            )
        }
    }
}

struct Declaration {
    exact_item: String,
    outcome: Outcome,
    detail: String,
}

#[derive(Default)]
pub(super) struct Scripts {
    by_logical_item: BTreeMap<String, Vec<Declaration>>,
}

impl Scripts {
    pub(super) fn inspect(&mut self, url: &Url, document: &str, exact_item: &str, location: &str) {
        let Some(libraries) = SNAPSHOT.as_ref() else {
            return;
        };
        let path = url.path();
        let filename = path.rsplit('/').next().unwrap_or_default();
        let filename_offset = path.len() - filename.len();
        for library in libraries {
            // Work with the exact capture positions. Other numbers in the URL can identify
            // a different asset, even when they happen to equal the declared version.
            let captures: BTreeSet<_> = library
                .filename
                .iter()
                .map(|pattern| (pattern, filename, filename_offset))
                .chain(library.uri.iter().map(|pattern| (pattern, path, 0)))
                .filter_map(|(pattern, input, offset)| {
                    let version = pattern.captures(input)?.get(1)?;
                    Some((offset + version.start(), offset + version.end()))
                })
                .collect();
            if captures.is_empty() {
                continue;
            }
            let mut path_parts = Vec::new();
            let mut versions = BTreeSet::new();
            let mut end = 0;
            for (start, stop) in captures {
                versions.insert(&path[start..stop]);
                if start >= end {
                    path_parts.push(&path[end..start]);
                }
                end = end.max(stop);
            }
            path_parts.push(&path[end..]);
            let key = serde_json::to_vec(&(
                document,
                url.origin().ascii_serialization(),
                path_parts,
                url.query(),
                &library.name,
            ))
            .expect("serialize declared library identity");
            let item = format!("{}/{}", super::identity("library", &key), library.name);
            let declarations = self.by_logical_item.entry(item).or_default();
            for (i, declared) in versions.into_iter().enumerate() {
                let (outcome, detail) = library.assess(declared);
                declarations.push(Declaration {
                    exact_item: format!("{exact_item}/{}/{i}", library.name),
                    outcome,
                    detail: format!(
                        "{} · {detail} · {location} · Declared filenames and URLs only",
                        library.name
                    ),
                });
            }
        }
    }

    pub(super) fn report(self, push: &mut impl FnMut(&str, &str, Outcome, &str)) {
        if self.by_logical_item.is_empty() {
            let reason = if SNAPSHOT.is_none() {
                "Retire.js data is unavailable for this scan"
            } else {
                "No library with an identifiable version was found in HTML script filenames or URLs"
            };
            push(RULE, "document", Insufficient, reason);
        }
        for (item, declarations) in self.by_logical_item {
            let ambiguous = declarations.len() > 1;
            for mut declaration in declarations {
                if ambiguous {
                    if declaration.outcome == Passed {
                        declaration.outcome = Insufficient;
                    }
                    declaration.detail.push_str(
                        " · Multiple declarations match across scans, so a fix cannot be verified",
                    );
                    push(
                        RULE,
                        &format!("ambiguous/{}", declaration.exact_item),
                        declaration.outcome,
                        &declaration.detail,
                    );
                } else {
                    push(RULE, &item, declaration.outcome, &declaration.detail);
                }
            }
        }
    }
}
