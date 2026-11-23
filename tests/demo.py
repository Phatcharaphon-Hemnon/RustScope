"""Drive the local app over HTTP with temporary accounts and an isolated SQLite DB."""
import argparse
import http.cookiejar
import json
import os
import re
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser


class Page(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append(dict(attrs))

    def value(self, name):
        return next(tag["value"] for tag in self.tags if tag.get("name") == name)


class Browser:
    def __init__(self, origin):
        self.origin = origin
        self.http = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        )

    def request(self, path, fields=None, expected=200, headers=None):
        data = None if fields is None else urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(
            self.origin + path, data, {"Origin": self.origin, **(headers or {})}
        )
        try:
            response = self.http.open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read().decode()
            assert response.status == expected, (path, response.status, body[:150])
            if expected == 200:
                assert response.headers["Referrer-Policy"] == "same-origin"
            return urllib.parse.urlsplit(response.url).path, body


def run(binary, state, output=None, rounds_dir=None):
    env = dict(os.environ, RUSTSCOPE_STATE=str(state), RUSTSCOPE_PORT="0")
    accounts = {
        name: subprocess.check_output([binary, "account", name], env=env, text=True).strip()
        for name in ("owner", "auditor", "reader")
    }
    server = subprocess.Popen([binary], env=env, stdout=subprocess.PIPE, text=True)
    try:
        line = server.stdout.readline()
        assert line.startswith("RustScope http://127.0.0.1:"), line
        origin = line.split()[1]
        localhost = Browser(origin.replace("127.0.0.1", "localhost"))
        _, login_html = localhost.request("/login")
        assert 'href="/register"' in login_html
        assert '<html lang="en">' in login_html and "<h1>Sign in</h1>" in login_html
        _, registration = localhost.request("/register?lang=th", headers={"Cookie": "rustscope_lang=th"})
        assert '<html lang="en">' in registration and "<h1>Create account</h1>" in registration
        _, registration_error = localhost.request("/register", {}, 400)
        assert "Enter a valid username" in registration_error
        visitor = Browser(origin)
        _, registration_html = visitor.request("/register")
        assert 'name="confirm_password"' in registration_html
        password = " a local demo password "
        registration = dict(user="registered", password=password, confirm_password=password)
        visitor.request("/register", registration, 403, {"Origin": "https://example.invalid"})
        visitor.request("/register", dict(registration, user="../owner"), 400)
        visitor.request("/register", dict(registration, confirm_password="different"), 400)
        visitor.request("/register", dict(registration, password="short", confirm_password="short"), 400)
        path, home_html = visitor.request("/register", registration)
        assert path == "/"
        Page(home_html).value("csrf")
        visitor.request("/register", dict(registration, user="owner"), 409)
        visitor.request("/register", registration, 409)
        fresh = Browser(origin)
        fresh.request("/login", dict(user="registered", password=password.strip()), 403)
        _, home_html = fresh.request("/login", dict(user="registered", password=password))
        logout_token = Page(home_html).value("csrf")
        fresh.request("/logout", {"csrf": "invalid"}, 403)
        fresh.request("/logout", {"csrf": logout_token})
        assert fresh.request("/")[0] == "/login"
        credentials = {"user": "owner", "password": accounts["owner"]}
        localhost.request("/login", credentials, 403, {"Origin": origin})
        localhost.request("/login", credentials, 403, {"Origin": "null"})
        _, body = localhost.request("/login", credentials)
        Page(body).value("csrf")
        Browser(origin).request("/login", expected=403, headers={"Host": "example.invalid"})
        clients = {}
        tokens = {}
        for name, password in accounts.items():
            clients[name] = Browser(origin)
            _, body = clients[name].request("/login", {"user": name, "password": password})
            tokens[name] = Page(body).value("csrf")
        owner, auditor, reader = (clients[k] for k in ("owner", "auditor", "reader"))
        csrf = tokens["owner"]
        _, home_html = owner.request("/")
        assert 'href="/sample-report.pdf"' in home_html
        with Browser(origin).http.open(origin + "/sample-report.pdf") as sample:
            assert sample.headers.get_content_type() == "application/pdf"
            assert sample.read() == Path("examples/reports/fixed.pdf").read_bytes()
        assert '<h1 class="dashboard-heading">Projects</h1>' in home_html
        _, catalog = owner.request("/catalog")
        assert 'data-id="A01-01" data-name="Access matrix"' in catalog
        assert 'data-id="A10-06" data-name="Resource cleanup"' in catalog
        live = dict(csrf=csrf, mode="live", name="Authorized website", days=7, upgrade="on")
        _, error_form = owner.request("/projects", live, expected=400)
        assert "Enter a scope URL" in error_form
        assert Page(error_form).value("name") == live["name"]
        _, error_form = owner.request("/projects", dict(live, base="https://example.invalid/app?q=1"), expected=400)
        assert "Use an HTTP or HTTPS URL" in error_form
        live_path, live_page = owner.request("/projects", dict(live, base="https://example.invalid/app"))
        assert "/verify" in live_page and 'name="target"' not in live_page
        assert live_page.index("/verify") < live_page.index("Scan history")
        assert live_path.startswith("/p/")
        assert "https://example.invalid/app/rustscope-verification.txt" in live_page
        assert "http://example.invalid/" not in live_page
        _, error_form = owner.request("/projects", dict(live, base="http://example.invalid:8080/app"), expected=400)
        assert "port 80" in error_form
        _, paired_page = owner.request("/projects", dict(live, base="http://example.invalid/app"))
        assert "http://example.invalid/app/rustscope-verification.txt" in paired_page
        assert "Publish the same verification file at the equivalent HTTPS URL" in paired_page
        owner.request(live_path + "/member", dict(csrf=csrf, user="reader", role="viewer"))
        for route in ("/", live_path):
            _, member_page = reader.request(route)
            assert "https://example.invalid" in member_page
            assert "https://example.invalid/app" not in member_page
            assert 'data-copy=' not in member_page
        loopback, _ = owner.request("/projects", dict(live, base="http://127.0.0.1", upgrade=""))
        _, verify_error = owner.request(loopback + "/verify", {"csrf": csrf}, expected=422)
        assert "public IPv4 address" in verify_error
        assert "http://127.0.0.1/rustscope-verification.txt" in verify_error
        project, body = owner.request("/projects", dict(csrf=csrf, mode="demo", name="Acceptance", days=1))
        assert all(f"A{c:02}-{n:02}" in body for c in range(1, 11) for n in range(1, 7))
        assert body.index('name="target"') < body.index('name="release"') < body.index("Scan history")
        _, project_html = owner.request(project)
        assert "Prepare scan" in project_html and "URL checks" in project_html
        auditor.request(project, expected=403)
        owner.request(project + "/member", dict(csrf="bad", user="reader", role="viewer"), 403)
        for user, role in (("reader", "viewer"), ("auditor", "reviewer")):
            owner.request(project + "/member", dict(csrf=csrf, user=user, role=role))
        _, viewer_page = reader.request(project)
        assert "Scan history" in viewer_page and 'name="target"' not in viewer_page
        db = sqlite3.connect(state / "rustscope.sqlite")
        live_id = live_path.rsplit('/', 1)[1]
        old_scope = json.loads(db.execute("select data from projects where id=?", (live_id,)).fetchone()[0])
        db.execute("update projects set data=json_set(data, '$.expires', 0, '$.verified', json('true')) where id=?",
                   (live_id,))
        db.commit()
        owner.request(live_path + "/renew", dict(csrf=csrf, days=31), 400)
        renewed_live, renewed_page = owner.request(live_path + "/renew", dict(csrf=csrf, days=7))
        new_scope = json.loads(db.execute("select data from projects where id=?", (live_id,)).fetchone()[0])
        assert renewed_live == live_path and new_scope["base"] == old_scope["base"]
        assert new_scope["challenge"] != old_scope["challenge"] and not new_scope["verified"]
        assert new_scope["challenge"] in renewed_page
        owner.request(live_path + "/scan", dict(csrf=csrf), 403)
        reports = {}
        for fixture, change in (("issue", "New"), ("forbidden", "NotComparable"),
                                ("persistent", "Persistent"), ("fixed", "VerifiedFixed")):
            if fixture == "persistent":
                db.execute("update projects set data=json_set(data, '$.expires', 0) where id=?",
                           (project.rsplit('/', 1)[1],))
                db.commit()
                owner.request(project + "/scan", fields, expected=403)
                reader.request(project + "/renew", dict(csrf=tokens["reader"], days=7), 403)
                renewed, _ = owner.request(project + "/renew", dict(csrf=csrf, days=7))
                assert renewed == project, "renewal changed project identity"
                owner.request(reports["issue"])
            _, project_html = owner.request(project)
            fields = dict(csrf=csrf, release=fixture, target="https://fixture.invalid/login",
                          fixture=fixture, sri="on", download="on", hsts_min=3600,
                          expected_form="login", request_id=Page(project_html).value("request_id"))
            if fixture == "issue":
                too_large = "é" * 131072 + "a"
                _, error = owner.request(project + "/scan", dict(fields, lock=too_large), 400)
                assert "Cargo.lock exceeds 262,144 bytes" in error and too_large in error
                lock = (Path(__file__).resolve().parents[1] / "fixtures/demo/dependencies.lock").read_text()
                lock += ('\n# PREVIEW_TEST_RAW_LOCK\n[[package]]\nname = "rustscope-preview-fixture"\n'
                         'version = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
                _, preview = owner.request(project + "/scan", dict(fields, preview="on", lock=lock))
                assert "A04-02" in preview and "A03-01" in preview
                assert 'id="scan-readiness"' in preview
                assert 'PREVIEW_TEST_RAW_LOCK' not in preview
                assert Page(preview).value("release") == fixture
                assert Page(preview).value("target") == fields["target"]
                fields["has_preview"] = Page(preview).value("has_preview")
                assert db.execute("select count(*) from scans").fetchone() == (0,)
                # Hold the first claim in this temporary DB so the HTTP waiting state is observable.
                db.execute("""CREATE TRIGGER hold_claim BEFORE UPDATE OF status ON scans
                              WHEN NEW.status = 'running' BEGIN SELECT RAISE(IGNORE); END""")
            path, body = owner.request(project + "/scan", fields)
            if fixture == "issue":
                assert 'data-status="queued"' in body and 'http-equiv="refresh"' in body
                db.execute("DROP TRIGGER hold_claim")
            same, _ = owner.request(project + "/scan", fields)
            assert path == same, "retry created a new scan"
            for _ in range(100):
                tags = Page(body).tags
                if any(t.get("data-rule") == "A04-02" and t.get("data-change") == change for t in tags):
                    break
                time.sleep(0.05)
                _, body = owner.request(path)
            else:
                raise AssertionError(f"expected A04-02 {change} for {fixture}")
            assert "SIMULATED_SECRET" not in body and "@media print" in body
            assert "Extensions" in body and "/ 60 standard rules" in body
            if fixture == "issue":
                assert "crates.io:rustscope-preview-fixture" in body, "previewed lockfile results were lost"
            rule = None
            for tag in tags:
                rule = tag.get("data-rule", rule)
                if rule == "X03-01" and tag.get("data-outcome") == "Insufficient":
                    break
            else:
                raise AssertionError(f"expected X03-01 insufficient evidence for {fixture}")
            if fixture == "forbidden":
                assert "403" in body
                _, full_report = owner.request(path + "?view=full&lang=th")
                assert "Assessment report" in full_report
                assert "Incomplete evidence from HTTP response 403" in full_report
                assert "Not comparable" in full_report
                assert '<html lang="en">' in full_report
                assert any(t.get("data-rule") == "A04-02" and t.get("data-change") == change
                           for t in Page(full_report).tags)
            reports[fixture] = path
            print(f"{fixture:12} A04-02 {change}")
        sid = path.split("/")[-1]
        other, _ = reader.request("/projects", dict(csrf=tokens["reader"], mode="demo", name="Private", days=1))
        owner.request(other, expected=403)
        owner.request(other + "/s/" + sid, expected=403)
        reader.request(other + "/s/" + sid, expected=403)
        data_before = db.execute("select data from scans where id=?", (sid,)).fetchone()
        review = dict(rule="A01-01", decision="Passed", rationale="Release evidence meets the criteria",
                      evidence=json.dumps(dict(case_id="ACL-01", commit="abc1234", environment="test",
                                               expected="deny", actual="deny", timestamp=int(time.time()))))
        reader.request(path + "/review", dict(csrf=tokens["reader"], **review), 403)
        _, body = auditor.request(path + "/review", dict(csrf=tokens["auditor"], **review))
        assert "ACL-01" in body and "auditor" in body and "abc1234" in body
        _, review_report = owner.request(path)
        assert "Release evidence meets the criteria" in review_report
        assert any(
            t.get("value") == review["rationale"] for t in Page(review_report).tags
        )
        assert data_before == db.execute("select data from scans where id=?", (sid,)).fetchone()
        assert db.execute("select count(*) from scans").fetchone() == (4,)
        persisted = "\n".join(db.iterdump())
        assert "SIMULATED_SECRET" not in persisted and "PREVIEW_TEST_RAW_LOCK" not in persisted
        db.close()
        def export_report(path):
            _, html = reader.request(path + "?view=full")
            # Saved HTML is shared independently of the viewer's account session.
            html = re.sub(r'<header class="banner">.*?</header>', '', html, count=1, flags=re.S)
            assert tokens["reader"] not in html
            return html

        if rounds_dir:
            rounds_dir.mkdir(parents=True, exist_ok=True)
            for fixture, path_to_round in reports.items():
                html = export_report(path_to_round)
                (rounds_dir / f"{fixture}.html").write_text(html, encoding="utf-8")
        if output:
            # Export the viewer's read-only report so the demo never saves a session token.
            output.write_text(export_report(path))
        # Emulate a database created before English became the default.
        with sqlite3.connect(state / "rustscope.sqlite") as legacy:
            project_id = project.rsplit("/", 1)[-1]
            forbidden_id = reports["forbidden"].rsplit("/", 1)[-1]
            project_name = "เว็บไซต์ตัวอย่าง"
            legacy.execute("UPDATE projects SET data=json_set(data, '$.name', ?) WHERE id=?",
                           (project_name, project_id))
            legacy.execute("""UPDATE scans SET data=json_set(data, '$.results',
                           json(replace(json_extract(data, '$.results'), ?, ?))) WHERE id=?""",
                           ("Incomplete evidence from HTTP response 403",
                            "ไม่มีหลักฐานครบถ้วนจากคำตอบ HTTP 403", forbidden_id))
            legacy.execute("UPDATE reviews SET data=json_set(data, '$.rationale', ?) WHERE scan=?",
                           ("หลักฐานของรุ่นนี้ตรงตามเกณฑ์", sid))
            legacy.commit()

            def records():
                return tuple(legacy.execute("SELECT data FROM " + table + " ORDER BY rowid").fetchall()
                             for table in ("projects", "scans", "reviews"))

            originals = records()
            assert any("ไม่มีหลักฐานครบถ้วน" in row[0] for row in originals[1])
            _, historical_scan = reader.request(reports["forbidden"])
            _, historical_review = reader.request(path)
            assert project_name in historical_scan
            assert "Incomplete evidence from HTTP response 403" in historical_scan
            assert "Release evidence meets the criteria" in historical_review
            assert records() == originals
        print("Passed scope isolation, CSRF, retry, secret redaction, and append-only review checks.")
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="save the synthetic English print view as HTML")
    parser.add_argument("--rounds-dir", type=Path, help="export all four synthetic English reports as HTML")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="rustscope-demo-") as temp:
        run(Path("target/debug/rustscope").resolve(), Path(temp), args.report, args.rounds_dir)
