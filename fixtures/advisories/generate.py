"""Print the normalized RustSec snapshot from a local advisory-db checkout."""

import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tomllib

checkout = pathlib.Path(sys.argv[1])
commit, date = subprocess.check_output(
    ["git", "-C", checkout, "log", "-1", "--format=%H %cs"],
    text=True,
).split()

# Read committed files so the snapshot always corresponds to the recorded commit.
archive = tarfile.open(fileobj=io.BytesIO(subprocess.check_output(
    ["git", "-C", checkout, "archive", commit, "crates"],
)))
advisories = {}
attributions = {}
for member in archive:
    if not member.isfile() or not member.name.endswith(".md"):
        continue
    markup = archive.extractfile(member).read().decode()
    source = tomllib.loads(markup.split("```", 2)[1].removeprefix("toml\n"))
    advisory = source["advisory"]
    kind = advisory.get("informational", "vulnerability")
    if kind not in ("vulnerability", "unmaintained"):
        continue
    if advisory.get("source") is not None:
        raise ValueError(f"Unsupported advisory registry at {member.name}")
    record = {
        "id": advisory["id"],
        "kind": kind,
        "withdrawn": "withdrawn" in advisory,
        "excluded": source["versions"]["patched"] + source["versions"].get("unaffected", []),
    }
    if "license" in advisory:
        attributions[record["id"]] = [
            advisory["license"],
            advisory.get("url"),
            *[f"https://github.com/advisories/{alias}"
              for alias in advisory.get("aliases", []) if alias.startswith("GHSA-")],
        ]
    advisories.setdefault(advisory["package"], []).append(record)

print(f'{{"commit":"{commit}","date":"{date}","advisories":{{')
print(",\n".join(f"{json.dumps(name)}:{json.dumps(records, separators=(',', ':'))}"
                 for name, records in sorted(advisories.items())))
print('},"attributions":{')
print(",\n".join(f"{json.dumps(id)}:{json.dumps(links, separators=(',', ':'))}"
                 for id, links in sorted(attributions.items())))
print("}}")
