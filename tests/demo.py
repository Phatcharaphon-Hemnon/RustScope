"""Drive the local app over HTTP with temporary accounts and an isolated SQLite DB."""
import argparse
import http.cookiejar
import json
import os
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
        localhost.request("/login")
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
        live = dict(csrf=csrf, mode="live", name="Authorized website", days=7, upgrade="on")
        _, error_form = owner.request("/projects", live, expected=400)
        assert "กรุณากรอก URL ขอบเขต" in error_form
        assert Page(error_form).value("name") == live["name"]
        _, error_form = owner.request("/projects", dict(live, base="https://example.invalid/app?q=1"), expected=400)
        assert "ใช้ URL HTTP หรือ HTTPS" in error_form
        live_path, live_page = owner.request("/projects", dict(live, base="https://example.invalid/app"))
        assert live_path.startswith("/p/")
        assert "https://example.invalid/app/rustscope-verification.txt" in live_page
        assert "http://example.invalid/" not in live_page
        _, error_form = owner.request("/projects", dict(live, base="http://example.invalid:8080/app"), expected=400)
        assert "พอร์ต 80" in error_form
        _, paired_page = owner.request("/projects", dict(live, base="http://example.invalid/app"))
        assert "http://example.invalid/app/rustscope-verification.txt" in paired_page
        assert "เผยแพร่ไฟล์ยืนยันที่ URL เดียวกันผ่าน HTTPS" in paired_page
        loopback, _ = owner.request("/projects", dict(live, base="http://127.0.0.1", upgrade=""))
        _, verify_error = owner.request(loopback + "/verify", {"csrf": csrf}, expected=422)
        assert "IPv4 สาธารณะ" in verify_error
        assert "http://127.0.0.1/rustscope-verification.txt" in verify_error
        project, body = owner.request("/projects", dict(csrf=csrf, mode="demo", name="Acceptance", days=1))
        assert all(f"A{c:02}-{n:02}" in body for c in range(1, 11) for n in range(1, 7))
        auditor.request(project, expected=403)
        owner.request(project + "/member", dict(csrf="bad", user="reader", role="viewer"), 403)
        for user, role in (("reader", "viewer"), ("auditor", "reviewer")):
            owner.request(project + "/member", dict(csrf=csrf, user=user, role=role))
        db = sqlite3.connect(state / "rustscope.sqlite")
        reports = {}
        for fixture, change in (("issue", "New"), ("forbidden", "NotComparable"),
                                ("persistent", "Persistent"), ("fixed", "VerifiedFixed")):
            _, project_html = owner.request(project)
            fields = dict(csrf=csrf, release=fixture, target="https://fixture.invalid/login",
                          fixture=fixture, sri="on", download="on", hsts_min=3600,
                          expected_form="login", request_id=Page(project_html).value("request_id"))
            if fixture == "issue":
                _, preview = owner.request(project + "/scan", dict(fields, preview="on"))
                assert "A04-02" in preview and "A03-01" in preview
                assert db.execute("select count(*) from scans").fetchone() == (0,)
            path, body = owner.request(project + "/scan", fields)
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
            assert "ส่วนขยาย" in body and "/ 60 กฎมาตรฐาน" in body
            rule = None
            for tag in tags:
                rule = tag.get("data-rule", rule)
                if rule == "X03-01" and tag.get("data-outcome") == "Insufficient":
                    break
            else:
                raise AssertionError(f"expected X03-01 insufficient evidence for {fixture}")
            if fixture == "forbidden":
                assert "403" in body
            reports[fixture] = path
            print(f"{fixture:12} A04-02 {change}")
        sid = path.split("/")[-1]
        other, _ = reader.request("/projects", dict(csrf=tokens["reader"], mode="demo", name="Private", days=1))
        owner.request(other, expected=403)
        owner.request(other + "/s/" + sid, expected=403)
        reader.request(other + "/s/" + sid, expected=403)
        data_before = db.execute("select data from scans where id=?", (sid,)).fetchone()
        review = dict(rule="A01-01", decision="Passed", rationale="หลักฐานของรุ่นนี้ตรงตามเกณฑ์",
                      evidence=json.dumps(dict(case_id="ACL-01", commit="abc1234", environment="test",
                                               expected="deny", actual="deny", timestamp=int(time.time()))))
        reader.request(path + "/review", dict(csrf=tokens["reader"], **review), 403)
        _, body = auditor.request(path + "/review", dict(csrf=tokens["auditor"], **review))
        assert "ACL-01" in body and "auditor" in body and "abc1234" in body
        assert data_before == db.execute("select data from scans where id=?", (sid,)).fetchone()
        assert db.execute("select count(*) from scans").fetchone() == (4,)
        assert "SIMULATED_SECRET" not in "\n".join(db.iterdump())
        db.close()
        if rounds_dir:
            rounds_dir.mkdir(parents=True, exist_ok=True)
            for fixture, path_to_round in reports.items():
                _, html = reader.request(path_to_round)
                assert tokens["reader"] not in html
                (rounds_dir / f"{fixture}.html").write_text(html, encoding="utf-8")
        if output:
            # Export the viewer's read-only report so the demo never saves a session token.
            _, report = reader.request(path)
            assert tokens["reader"] not in report
            output.write_text(report)
        print("Passed scope isolation, CSRF, retry, secret redaction, and append-only review checks.")
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="save the synthetic Thai print view as HTML")
    parser.add_argument("--rounds-dir", type=Path, help="export all four synthetic Thai reports as HTML")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="rustscope-demo-") as temp:
        run(Path("target/debug/rustscope").resolve(), Path(temp), args.report, args.rounds_dir)
