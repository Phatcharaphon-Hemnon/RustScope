//! Passive checks over the collected document and response headers.
mod javascript;

use crate::{
    domain::{Observation, Outcome, Outcome::*},
    model::Policy,
    scope::{HttpEvidence, safe_url},
};
use base64::{Engine, engine::general_purpose as encoding};
use scraper::{ElementRef, Html, Selector};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use url::Url;

pub fn evaluate(response: Result<&HttpEvidence, &str>, policy: &Policy) -> Vec<Observation> {
    let mut results: Vec<Observation> = Vec::new();
    let mut indexes = HashMap::<_, usize>::new();
    let priority = |outcome| match outcome {
        Finding => 4,
        Insufficient => 3,
        Review => 2,
        Passed => 1,
        Na => 0,
    };
    let mut push = |rule: &str, item: &str, outcome: Outcome, observed: &str| {
        let index = *indexes
            .entry((rule.to_owned(), item.to_owned()))
            .or_insert(results.len());
        if let Some(existing) = results.get_mut(index) {
            if priority(outcome) > priority(existing.outcome) {
                existing.outcome = outcome;
                existing.observed = observed.into();
            }
        } else {
            results.push(Observation {
                rule: rule.into(),
                item: item.into(),
                outcome,
                observed: observed.into(),
            });
        }
    };
    let evidence = match response {
        Ok(response) if (200..300).contains(&response.status) && response.status != 206 => {
            Url::parse(&response.final_url).ok().and_then(|url| {
                (matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
                    .then_some((response, url))
            })
        }
        _ => None,
    };
    let Some((response, document_url)) = evidence else {
        let reason = match response {
            Ok(response) => format!("ไม่มีหลักฐานครบถ้วนจากคำตอบ HTTP {}", response.status),
            Err(_) => "ไม่สามารถเก็บหลักฐานจากเป้าหมาย".into(),
        };
        for (rule, item, applicable) in [
            ("A02-01", "download", policy.download),
            ("A02-02", "host", policy.hsts_min.is_some()),
            ("A04-01", "document", true),
            ("A04-02", "document", true),
            ("A04-03", "document", true),
            ("A08-04", "document", policy.sri),
            (javascript::RULE, "document", true),
        ] {
            let (outcome, observed) = if applicable {
                (Insufficient, reason.as_str())
            } else {
                (Na, "นโยบายไม่ได้ระบุให้ตรวจ")
            };
            push(rule, item, outcome, observed);
        }
        return results;
    };

    let header = |name| response.headers.get(name).map(String::as_str);
    let (outcome, observed) = match (policy.download, header("x-content-type-options")) {
        (false, _) => (Na, "นโยบายไม่ได้ระบุว่าเป็นไฟล์ดาวน์โหลด"),
        (true, Some(value)) if value.trim().eq_ignore_ascii_case("nosniff") => {
            (Passed, "พบ X-Content-Type-Options: nosniff")
        }
        (true, Some(_)) => (Finding, "ค่า X-Content-Type-Options ไม่ใช่ nosniff"),
        (true, None) => (Finding, "ไม่พบ X-Content-Type-Options"),
    };
    let resource = identity("download", document_url.as_str().as_bytes());
    push("A02-01", &resource, outcome, observed);

    let https = document_url.scheme() == "https";
    let (outcome, observed) = match (https, policy.hsts_min, header("strict-transport-security")) {
        (_, None, _) => (Na, "ไม่ได้กำหนดอายุขั้นต่ำของ HSTS".into()),
        (false, _, _) => (Na, "ปลายทางตอบผ่าน HTTP".into()),
        (true, Some(_), None) => (Finding, "ไม่พบ Strict-Transport-Security".into()),
        (true, Some(min), Some(value)) => match hsts_age(value) {
            Some(age) if age > 0 && age >= min => (Passed, format!("อายุ HSTS {age} วินาที")),
            Some(age) => (
                Finding,
                format!("อายุ HSTS {age} วินาที นโยบายกำหนดขั้นต่ำ {min} วินาที และต้องมากกว่าศูนย์"),
            ),
            None => (Finding, "รูปแบบ Strict-Transport-Security ไม่ถูกต้อง".into()),
        },
    };
    push(
        "A02-02",
        &safe_url(document_url.as_str()),
        outcome,
        &observed,
    );

    let html = header("content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"))
    });
    if !html || response.body.trim().is_empty() {
        push(
            javascript::RULE,
            "document",
            Insufficient,
            "ไม่มีเนื้อหา HTML ที่ตรวจได้",
        );
        for (rule, applicable) in [
            ("A04-01", true),
            ("A04-02", true),
            ("A04-03", https),
            ("A08-04", policy.sri),
        ] {
            let form_expected =
                matches!(rule, "A04-01" | "A04-02") && policy.expected_form.is_some();
            let (outcome, observed) = if !applicable {
                (Na, "อยู่นอกเงื่อนไขของกฎ")
            } else if policy.download && !html && !form_expected {
                (Na, "ไฟล์ดาวน์โหลดไม่ได้เป็น HTML")
            } else {
                (Insufficient, "ไม่มีเนื้อหา HTML ที่ตรวจได้")
            };
            push(rule, "document", outcome, observed);
        }
        return results;
    }

    let document = Html::parse_document(&response.body);
    let base = document
        .select(&selector("base[href]"))
        .next()
        .and_then(|element| document_url.join(element.attr("href")?).ok())
        .filter(|url| !matches!(url.scheme(), "data" | "javascript"))
        .unwrap_or_else(|| document_url.clone());
    let mut web = Document {
        html: &document,
        url: &document_url,
        base: &base,
        policy,
        push,
    };
    web.forms();
    web.scripts();
    results
}

fn selector(css: &str) -> Selector {
    Selector::parse(css).expect("fixed selector")
}

fn trim_html(value: &str) -> &str {
    value.trim_matches(|ch: char| ch.is_ascii_whitespace())
}

fn identity(kind: &str, value: &[u8]) -> String {
    format!("{kind}/{}", hex::encode(Sha256::digest(value)))
}

pub(crate) fn redacted_location(url: &Url) -> String {
    let path = identity("path", url.path().as_bytes());
    format!("{} ({path})", safe_url(url.as_str()))
}

fn resource_key(url: &Url) -> String {
    format!("{:?}|{:?}|{}", url.host(), url.port(), url.path())
}

fn hsts_age(value: &str) -> Option<u64> {
    fn token(value: &str) -> bool {
        !value.is_empty()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^`_|~".contains(&b))
    }
    let mut seen = BTreeSet::new();
    let mut age = None;
    let mut directives = value.trim();
    while !directives.is_empty() {
        let end = directives.find(['=', ';']).unwrap_or(directives.len());
        let name = directives[..end].trim().to_ascii_lowercase();
        let mut rest = &directives[end..];
        let mut argument = None;
        if let Some(value) = rest.strip_prefix('=') {
            rest = value.trim_start();
            if let Some(mut quoted) = rest.strip_prefix('"') {
                let mut decoded = String::new();
                loop {
                    let ch = quoted.chars().next()?;
                    quoted = &quoted[ch.len_utf8()..];
                    if ch == '"' {
                        break;
                    }
                    if ch == '\\' {
                        let escaped = quoted.chars().next()?;
                        decoded.push(escaped);
                        quoted = &quoted[escaped.len_utf8()..];
                    } else if ch == '\t' || ch.is_ascii_graphic() || ch == ' ' {
                        decoded.push(ch);
                    } else {
                        return None;
                    }
                }
                argument = Some(decoded);
                rest = quoted.trim_start();
            } else {
                let end = rest.find(';').unwrap_or(rest.len());
                let value = rest[..end].trim_end();
                if !token(value) {
                    return None;
                }
                argument = Some(value.to_owned());
                rest = &rest[end..];
            }
        }
        if !name.is_empty() || argument.is_some() {
            if !token(&name) || !seen.insert(name.clone()) {
                return None;
            }
            match name.as_str() {
                "max-age" => {
                    let value = argument?;
                    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                        return None;
                    }
                    age = Some(value.parse().unwrap_or(u64::MAX));
                }
                "includesubdomains" if argument.is_some() => return None,
                _ => {}
            }
        }
        directives = if rest.is_empty() {
            rest
        } else {
            rest.strip_prefix(';')?.trim_start()
        };
    }
    age
}

struct Document<'a, F> {
    html: &'a Html,
    url: &'a Url,
    base: &'a Url,
    policy: &'a Policy,
    push: F,
}

impl<F: FnMut(&str, &str, Outcome, &str)> Document<'_, F> {
    fn forms(&mut self) {
        let mut elements_by_id = HashMap::new();
        let mut id_counts = HashMap::new();
        for element in self.html.select(&selector("[id]")) {
            if let Some(id) = element.attr("id") {
                elements_by_id.entry(id).or_insert(element);
                *id_counts.entry(id).or_insert(0) += 1;
            }
        }
        let owner = |control: ElementRef<'_>| {
            if let Some(id) = control.attr("form") {
                return elements_by_id
                    .get(id)
                    .filter(|element| element.value().name() == "form")
                    .map(|element| element.id());
            }
            control
                .ancestors()
                .filter_map(ElementRef::wrap)
                .find(|element| element.value().name() == "form")
                .map(|element| element.id())
        };
        let mut controls = HashMap::<_, Vec<_>>::new();
        for control in self.html.select(&selector("input, button")) {
            if let Some(form) = owner(control) {
                controls.entry(form).or_default().push(control);
            }
        }

        let document_key = resource_key(self.url);
        let document_location = redacted_location(self.url);
        let mut expected = false;
        let mut inspected = Vec::new();
        let mut counts = HashMap::new();
        for form in self.html.select(&selector("form")) {
            let Some(owned) = controls.get(&form.id()) else {
                continue;
            };
            let password = |control: &ElementRef<'_>| {
                control.value().name() == "input"
                    && control
                        .attr("type")
                        .is_some_and(|kind| kind.eq_ignore_ascii_case("password"))
            };
            if !owned.iter().any(password) {
                continue;
            }
            expected |= self
                .policy
                .expected_form
                .as_deref()
                .is_some_and(|id| form.attr("id") == Some(id));
            let id = form.attr("id").filter(|id| !id.is_empty());
            let form_name = form.attr("name").filter(|name| !name.is_empty());
            let names: Vec<_> = owned
                .iter()
                .filter(|control| password(control))
                .filter_map(|control| control.attr("name").filter(|name| !name.is_empty()))
                .collect();
            let stable = match id {
                Some(id) => id_counts[id] == 1,
                None => form_name.is_some() || !names.is_empty(),
            };
            let semantic = if id.is_some() {
                (id, None, &[][..])
            } else {
                (None, form_name, names.as_slice())
            };
            let key =
                serde_json::to_vec(&(&document_key, semantic)).expect("serialize form identity");
            let item = identity("form", &key);
            *counts.entry(item.clone()).or_insert(0) += 1;
            let action = form.attr("action");
            let overrides = owned
                .iter()
                .filter(|control| {
                    let kind = control.attr("type").map(str::to_ascii_lowercase);
                    match control.value().name() {
                        "button" => !matches!(kind.as_deref(), Some("button" | "reset")),
                        _ => matches!(kind.as_deref(), Some("submit" | "image")),
                    }
                })
                .filter_map(|control| control.attr("formaction").map(Some));
            let mut destinations = std::iter::once(action).chain(overrides).map(|action| {
                match action.map(trim_html).filter(|value| !value.is_empty()) {
                    Some(value) => self.base.join(value).ok(),
                    None => Some(self.url.clone()),
                }
            });
            let mut bad = BTreeSet::new();
            let mut uncertain = false;
            for target in destinations.by_ref() {
                match target {
                    Some(url) if url.scheme() == "http" => {
                        bad.insert(redacted_location(&url));
                    }
                    Some(url) if url.scheme() == "https" => {}
                    _ => uncertain = true,
                }
            }
            let submission = if !bad.is_empty() {
                (
                    Finding,
                    format!(
                        "HTML จาก {document_location} ระบุปลายทาง HTTP: {}",
                        bad.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                )
            } else if uncertain {
                (Insufficient, "มีปลายทางฟอร์มที่ตรวจการใช้ HTTPS ไม่ได้".into())
            } else {
                (Passed, "ปลายทางฟอร์มและปุ่มส่งที่ระบุใช้ HTTPS".into())
            };
            inspected.push((item, submission, stable));
        }
        for (item, (outcome, observed), stable) in &inspected {
            let comparable = *stable && counts[item] == 1;
            // Ambiguous observations must never close against a later, unique form.
            let key = if comparable {
                item.clone()
            } else {
                format!("ambiguous/{item}")
            };
            let item = &key;
            let (transport, reason) = if self.url.scheme() == "http" {
                (Finding, "HTML ที่มีฟอร์มรหัสผ่านถูกส่งผ่าน HTTP")
            } else if !comparable {
                (Insufficient, "ฟอร์มไม่มีตัวระบุที่ใช้เทียบซ้ำได้")
            } else {
                (Passed, "HTML ที่มีฟอร์มรหัสผ่านถูกส่งผ่าน HTTPS")
            };
            (self.push)(
                "A04-01",
                item,
                transport,
                &format!("{reason} ที่ {document_location}"),
            );
            let (outcome, observed) = if *outcome == Passed && !comparable {
                (Insufficient, "ฟอร์มไม่มีตัวระบุที่ใช้เทียบซ้ำได้")
            } else {
                (*outcome, observed.as_str())
            };
            (self.push)("A04-02", item, outcome, observed);
        }
        let fallback = if self.policy.expected_form.is_some() && !expected {
            Some((Insufficient, "ไม่พบฟอร์มรหัสผ่านที่ระบุ"))
        } else if inspected.is_empty() && self.html.select(&selector("script")).next().is_some() {
            Some((
                Insufficient,
                "ไม่พบฟอร์มใน HTML ที่ได้รับ เนื้อหาอาจสร้างด้วย JavaScript",
            ))
        } else if inspected.is_empty() {
            Some((Na, "ไม่พบฟอร์มรหัสผ่านใน HTML"))
        } else {
            None
        };
        if let Some((outcome, observed)) = fallback {
            for rule in ["A04-01", "A04-02"] {
                (self.push)(rule, "document", outcome, observed);
            }
        }
    }

    fn scripts(&mut self) {
        let https = self.url.scheme() == "https";
        let mut mixed = false;
        let mut sri = false;
        let mut libraries = javascript::Scripts::default();
        let document = resource_key(self.url);
        for script in self.html.select(&selector("script[src]")) {
            let Some(src) = script
                .attr("src")
                .map(str::trim)
                .filter(|src| !src.is_empty())
            else {
                continue;
            };
            let Ok(url) = self.base.join(src) else {
                for (rule, applicable) in [("A04-03", https), ("A08-04", self.policy.sri)] {
                    if applicable {
                        (self.push)(
                            rule,
                            "document",
                            Insufficient,
                            "HTML ระบุ URL ของสคริปต์ที่อ่านไม่ได้",
                        );
                    }
                }
                mixed |= https;
                sri |= self.policy.sri;
                continue;
            };
            if !matches!(url.scheme(), "http" | "https") {
                continue;
            }
            let key = serde_json::to_vec(&(&document, resource_key(&url), url.query()))
                .expect("serialize script identity");
            let item = identity("script", &key);
            let location = redacted_location(&url);
            libraries.inspect(&url, &document, &item, &location);
            if https {
                mixed = true;
                let outcome = if url.scheme() == "http" {
                    Finding
                } else {
                    Passed
                };
                (self.push)(
                    "A04-03",
                    &item,
                    outcome,
                    &format!("HTML ระบุแหล่งสคริปต์ {location}"),
                );
            }
            if self.policy.sri && url.origin() != self.url.origin() {
                sri = true;
                let (outcome, detail) = match script.attr("integrity") {
                    Some(value) if valid_integrity(value) => {
                        (Passed, "รูปแบบ integrity ถูกต้อง ตรวจเฉพาะข้อมูลใน HTML")
                    }
                    Some(_) => (Finding, "รูปแบบ integrity ไม่ถูกต้อง"),
                    None => (Finding, "ไม่มี integrity"),
                };
                (self.push)(
                    "A08-04",
                    &item,
                    outcome,
                    &format!("แหล่งสคริปต์ {location}: {detail}"),
                );
            }
        }
        libraries.report(&mut self.push);
        if !mixed {
            let observed = if https {
                "ไม่มีแหล่งสคริปต์ HTTP(S) ใน HTML"
            } else {
                "เอกสารปลายทางไม่ได้ส่งผ่าน HTTPS"
            };
            (self.push)("A04-03", "document", Na, observed);
        }
        if !sri {
            let observed = if self.policy.sri {
                "ไม่พบสคริปต์ข้ามต้นทางใน HTML"
            } else {
                "นโยบายไม่ได้กำหนด SRI"
            };
            (self.push)("A08-04", "document", Na, observed);
        }
    }
}

fn valid_integrity(value: &str) -> bool {
    let mut expressions = value.split_ascii_whitespace().peekable();
    expressions.peek().is_some()
        && expressions.all(|expression| {
            let Some((algorithm, digest)) = expression.split_once('-') else {
                return false;
            };
            let (digest, options) = digest.split_once('?').unwrap_or((digest, ""));
            if !options.bytes().all(|byte| byte.is_ascii_graphic()) {
                return false;
            }
            let size = match algorithm {
                "sha256" => 32,
                "sha384" => 48,
                "sha512" => 64,
                _ => return false,
            };
            [
                &encoding::STANDARD,
                &encoding::STANDARD_NO_PAD,
                &encoding::URL_SAFE,
                &encoding::URL_SAFE_NO_PAD,
            ]
            .iter()
            .any(|engine| engine.decode(digest).is_ok_and(|bytes| bytes.len() == size))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(url: &str, body: &str) -> HttpEvidence {
        HttpEvidence {
            final_url: url.into(),
            status: 200,
            headers: [("content-type".into(), "text/html; charset=utf-8".into())].into(),
            body: body.into(),
        }
    }

    fn policy() -> Policy {
        Policy {
            download: false,
            hsts_min: None,
            sri: false,
            expected_form: None,
        }
    }

    fn for_rule(results: &[Observation], rule: &str) -> Vec<Outcome> {
        results
            .iter()
            .filter(|obs| obs.rule == rule)
            .map(|obs| obs.outcome)
            .collect()
    }

    #[test]
    fn header_findings_pass_applicability_and_collection_failure() {
        let mut page = evidence("https://site.test/download", "<p>fixture</p>");
        let mut policy = policy();
        for rule in ["A02-01", "A02-02"] {
            assert_eq!(for_rule(&evaluate(Ok(&page), &policy), rule), [Na]);
        }
        policy.download = true;
        policy.hsts_min = Some(120);
        assert_eq!(for_rule(&evaluate(Ok(&page), &policy), "A02-01"), [Finding]);
        assert_eq!(for_rule(&evaluate(Ok(&page), &policy), "A02-02"), [Finding]);
        for (header, value, rule, expected) in [
            ("x-content-type-options", "nonsense", "A02-01", Finding),
            ("x-content-type-options", " NoSnIfF ", "A02-01", Passed),
            ("strict-transport-security", "max-age=0", "A02-02", Finding),
            (
                "strict-transport-security",
                "max-age=119",
                "A02-02",
                Finding,
            ),
            (
                "strict-transport-security",
                "max-age=+120",
                "A02-02",
                Finding,
            ),
            (
                "strict-transport-security",
                "max-age=120; max-age=10",
                "A02-02",
                Finding,
            ),
            (
                "strict-transport-security",
                "max-age=120, max-age=10",
                "A02-02",
                Finding,
            ),
            (
                "strict-transport-security",
                "max-age=120; includeSubDomains=yes",
                "A02-02",
                Finding,
            ),
            (
                "strict-transport-security",
                "MAX-AGE=\"120\"; includeSubDomains; ext=\"a;b\"",
                "A02-02",
                Passed,
            ),
        ] {
            page.headers.insert(header.into(), value.into());
            assert_eq!(
                for_rule(&evaluate(Ok(&page), &policy), rule),
                [expected],
                "{value}"
            );
        }
        for rule in ["A02-01", "A02-02"] {
            assert_eq!(
                for_rule(&evaluate(Err("timeout secret"), &policy), rule),
                [Insufficient]
            );
        }
        page.final_url = "http://site.test/download".into();
        assert_eq!(for_rule(&evaluate(Ok(&page), &policy), "A02-02"), [Na]);
    }

    #[test]
    fn forms_use_final_document_and_base_with_stable_identity() {
        let mut page = evidence(
            "https://site.test/signin",
            r#"<base href="http://site.test/base/">
               <form id="secret-login" action="relative?secret-query=1"><input type=password value=secret-value></form>
               <form id="empty" action=""><input type=password></form>
               <input type=password form="external">
               <form id="external" action="https://site.test/post"></form>
               <button form="external" formaction="http://site.test/secret-path">Send</button>"#,
        );
        let mut policy = policy();
        policy.expected_form = Some("secret-login".into());
        let results = evaluate(Ok(&page), &policy);
        assert_eq!(for_rule(&results, "A04-01"), [Passed, Passed, Passed]);
        assert_eq!(for_rule(&results, "A04-02"), [Finding, Passed, Finding]);
        let before = results.iter().find(|obs| obs.rule == "A04-02").unwrap();
        assert!(before.observed.contains("http://site.test"));
        assert!(!serde_json::to_string(&results).unwrap().contains("secret-"));
        page.body =
            r#"<form id="secret-login" action="/updated"><input type=password></form>"#.into();
        let updated = evaluate(Ok(&page), &policy);
        let after = updated.iter().find(|obs| obs.rule == "A04-02").unwrap();
        assert_eq!(before.item, after.item);
        assert_eq!(after.outcome, Passed);
        page.final_url = "https://site.test/another-page".into();
        assert_ne!(
            before.item,
            evaluate(Ok(&page), &policy)
                .iter()
                .find(|obs| obs.rule == "A04-02")
                .unwrap()
                .item,
        );
        page.final_url = "http://site.test/signin".into();
        assert_eq!(for_rule(&evaluate(Ok(&page), &policy), "A04-01"), [Finding]);
        page.status = 403;
        let forbidden = evaluate(Ok(&page), &policy);
        assert_eq!(for_rule(&forbidden, "A04-02"), [Insufficient]);
        assert!(forbidden.iter().any(|obs| obs.observed.contains("403")));
        page.status = 200;
        page.body = "<p>Login moved</p>".into();
        assert_eq!(
            for_rule(&evaluate(Ok(&page), &policy), "A04-02"),
            [Insufficient]
        );
        policy.expected_form = None;
        assert_eq!(for_rule(&evaluate(Ok(&page), &policy), "A04-01"), [Na]);
        page.final_url = "https://site.test/signin".into();
        page.body = "<form><input type=password></form>".into();
        assert_eq!(
            for_rule(&evaluate(Ok(&page), &policy), "A04-02"),
            [Insufficient]
        );
        page.body = "<div id=app></div><script src='/app.js'></script>".into();
        assert_eq!(
            for_rule(&evaluate(Ok(&page), &policy), "A04-01"),
            [Insufficient]
        );
    }

    #[test]
    fn removing_a_duplicate_form_is_not_a_verified_fix() {
        let first = evidence(
            "https://example.test/forms",
            r#"<form id="x" action="http://example.test"><input type=password></form><form id="x"><input type=password></form>"#,
        );
        let second = evidence(
            "https://example.test/forms",
            r#"<form id="x"><input type=password></form>"#,
        );
        let before = evaluate(Ok(&first), &policy());
        let after = evaluate(Ok(&second), &policy());
        let open = before
            .iter()
            .find(|v| v.rule == "A04-02" && v.outcome == Finding)
            .unwrap();
        assert!(
            after
                .iter()
                .any(|v| v.rule == "A04-02" && v.outcome == Passed)
        );
        assert!(
            !after
                .iter()
                .any(|v| v.item == open.item && v.outcome == Passed)
        );
    }

    #[test]
    fn script_findings_and_passes_are_limited_to_html_declarations() {
        let mut policy = policy();
        let mut page = evidence(
            "https://site.test/app",
            r#"<script src="http://user:pass@cdn.test/secret-path?token=secret"></script>
               <script src="/same-origin" integrity="malformed"></script>
               <script src="//cdn.test/malformed" integrity="sha384-AAAA"></script>"#,
        );
        assert_eq!(for_rule(&evaluate(Ok(&page), &policy), "A08-04"), [Na]);
        policy.sri = true;
        let results = evaluate(Ok(&page), &policy);
        assert_eq!(for_rule(&results, "A04-03"), [Finding, Passed, Passed]);
        assert_eq!(for_rule(&results, "A08-04"), [Finding, Finding]);
        let observed = serde_json::to_string(&results).unwrap();
        assert!(observed.contains("http://cdn.test"));
        for secret in ["token", "secret", "user:", "pass@", "sha384-AAAA"] {
            assert!(!observed.contains(secret), "{secret}");
        }
        let digest = encoding::STANDARD.encode([0; 32]);
        page.body = format!(
            r#"<script src="https://cdn.test/secret-path?token=secret" integrity="sha256-{digest}"></script>"#
        );
        let fixed = evaluate(Ok(&page), &policy);
        assert_eq!(for_rule(&fixed, "A04-03"), [Passed]);
        assert_eq!(for_rule(&fixed, "A08-04"), [Passed]);
        assert!(!valid_integrity(&format!("sha256-{digest} sha512-invalid")));
        for rule in ["A04-03", "A08-04"] {
            assert_eq!(
                results.iter().find(|obs| obs.rule == rule).unwrap().item,
                fixed.iter().find(|obs| obs.rule == rule).unwrap().item
            );
            assert_eq!(
                for_rule(&evaluate(Err("timeout"), &policy), rule),
                [Insufficient]
            );
        }
        page.body
            .push_str(r#"<script src="https://cdn.test/secret-path?token=secret"></script>"#);
        assert_eq!(for_rule(&evaluate(Ok(&page), &policy), "A08-04"), [Finding]);
        page.body = "<script src='/same-origin'></script>".into();
        assert_eq!(for_rule(&evaluate(Ok(&page), &policy), "A08-04"), [Na]);
    }

    #[test]
    fn javascript_uses_resolved_url_and_reports_redacted_advisory_details() {
        for (body, origin) in [
            (
                r#"<script src="../private/jquery-3.4.1.min.js?sig=secret#fragment"></script>"#,
                "https://site.test",
            ),
            (
                r#"<script src="//cdn.test/private/jquery/3.4.1/jquery.min.js?sig=secret#fragment"></script>"#,
                "https://cdn.test",
            ),
            (
                r#"<base href="//cdn.test/private/jquery/3.4.1/">
                   <script src="jquery.min.js?sig=secret#fragment"></script>"#,
                "https://cdn.test",
            ),
            (
                r#"<base href="../private/3.4.1/">
                   <script src="jquery.min.js?sig=secret#fragment"></script>"#,
                "https://site.test",
            ),
        ] {
            let page = evidence("https://site.test/app/index.html", body);
            let results = evaluate(Ok(&page), &policy());
            assert_eq!(for_rule(&results, javascript::RULE), [Finding]);
            let observed = &results
                .iter()
                .find(|obs| obs.rule == javascript::RULE)
                .unwrap()
                .observed;
            for detail in [
                origin,
                "jquery",
                "3.4.1",
                "CVE-2020-11022",
                "GHSA-gxr4-xjj5-5px2",
                "รุ่นแรกที่แก้ไข: 3.5.0",
                "ตรวจเฉพาะชื่อไฟล์และ URL",
            ] {
                assert!(observed.contains(detail), "{detail}: {observed}");
            }
            for secret in ["private", "sig=", "secret", "fragment"] {
                assert!(!observed.contains(secret), "{secret}: {observed}");
            }
        }
    }

    #[test]
    fn javascript_requires_a_recognised_comparable_declared_version() {
        for (src, expected) in [
            ("assets/jquery-3.7.1.js", Passed),
            ("assets/jquery-3.5.0+build.1.min.js", Passed),
            ("assets/jquery-3.5.0-rc.1.min.js", Finding),
            ("assets/jquery-3.5.0-min.js", Finding),
            ("assets/bootstrap-4.0.0-alpha.1.js", Passed),
            ("assets/bootstrap-4.0.0-beta.js", Finding),
            ("assets/bootstrap-4.0.0-beta.2.js", Passed),
            ("assets/jquery-1.9.0b1.js", Insufficient),
            ("assets/jquery-3.4.js", Insufficient),
            ("assets/vendor-jquery-3.4.1.js", Insufficient),
            ("assets/jquery-890f984e77ad.js", Insufficient),
            ("assets/bundle.js?name=jquery-3.4.1.js", Insufficient),
            ("assets/jquery/3.4.1/jquery.min.js.bak", Insufficient),
        ] {
            let page = evidence(
                "http://site.test/",
                &format!(r#"<script src="{src}"></script>"#),
            );
            assert_eq!(
                for_rule(&evaluate(Ok(&page), &policy()), javascript::RULE),
                [expected],
                "{src}"
            );
        }

        let page = evidence("https://site.test/", "<p>Checkout</p>");
        assert_eq!(
            for_rule(&evaluate(Ok(&page), &policy()), javascript::RULE),
            [Insufficient]
        );
        assert_eq!(
            for_rule(&evaluate(Err("timeout"), &policy()), javascript::RULE),
            [Insufficient]
        );
    }

    #[test]
    fn javascript_compares_unique_version_updates_and_preserves_ambiguous_findings() {
        use crate::domain::{ChangeStatus, EvaluationProvenance, Round, compare};
        let observations = |urls: &[&str]| {
            let body = urls
                .iter()
                .map(|url| format!(r#"<script src="{url}"></script>"#))
                .collect::<String>();
            evaluate(Ok(&evidence("https://site.test/doc", &body)), &policy())
                .into_iter()
                .filter(|obs| obs.rule == javascript::RULE)
                .collect::<Vec<_>>()
        };
        let mut provenance = EvaluationProvenance::default();
        provenance.record_web_evaluation();
        let changes = |before: &[Observation], after: &[Observation]| {
            compare(&[before, after].map(|observations| Round {
                project: "p",
                target: "doc",
                policy: "same",
                version: "2",
                provenance: &provenance,
                observations,
            }))
        };
        for (old, fixed) in [
            (
                "/tenant/3.4.1/jquery-3.4.1.min.js",
                "/tenant/3.4.1/jquery-3.7.1.min.js",
            ),
            (
                "//cdn.test/jquery/3.4.1/jquery.min.js?cache=same",
                "//cdn.test/jquery/3.7.1/jquery.min.js?cache=same",
            ),
        ] {
            let before = observations(&[old]);
            let after = observations(&[fixed]);
            assert_eq!(before[0].item, after[0].item);
            assert_eq!(
                changes(&before, &after)[0].status,
                ChangeStatus::VerifiedFixed
            );
            let duplicate = observations(&[fixed, fixed]);
            assert_eq!(duplicate[0].outcome, Insufficient);
            assert_eq!(
                changes(&before, &duplicate)[0].status,
                ChangeStatus::NotComparable
            );
            let mixed = observations(&[old, fixed]);
            assert!(mixed.iter().any(|obs| obs.outcome == Finding));
            assert!(mixed.iter().all(|obs| obs.item.starts_with("ambiguous/")));
            assert!(
                changes(&mixed, &after)
                    .iter()
                    .all(|c| c.status == ChangeStatus::NotComparable)
            );
        }
        let before = observations(&["//cdn.test/tenant/3.4.1/jquery-3.4.1.min.js?key=a"]);
        for different in [
            "//other.test/tenant/3.4.1/jquery-3.7.1.min.js?key=a",
            "//cdn.test/tenant/3.7.1/jquery-3.7.1.min.js?key=a",
            "//cdn.test/tenant/3.4.1/jquery-3.7.1.min.js?key=b",
        ] {
            let after = observations(&[different]);
            assert_ne!(before[0].item, after[0].item);
            assert_eq!(
                changes(&before, &after)[0].status,
                ChangeStatus::NotComparable
            );
        }
    }
}
