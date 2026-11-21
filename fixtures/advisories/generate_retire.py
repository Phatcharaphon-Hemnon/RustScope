#!/usr/bin/env python3
"""Filter a pinned Retire.js jsrepository.json supplied on stdin."""

import json
import sys


def filter_repository(repository):
    result = {}
    for name, library in sorted(repository.items()):
        extractors = {
            kind: library["extractors"][kind]
            for kind in ("filename", "uri")
            if library["extractors"].get(kind)
        }
        if name == "retire-example" or not extractors or not library["vulnerabilities"]:
            continue

        vulnerabilities = []
        for advisory in library["vulnerabilities"]:
            identifiers = {
                kind: value if isinstance(value, list) else [value]
                for kind, value in advisory["identifiers"].items()
                if kind not in ("summary", "release")
            }
            entry = {key: advisory[key] for key in ("below", "atOrAbove", "severity") if key in advisory}
            vulnerabilities.append(dict(entry, identifiers=identifiers))
        result[name] = dict(extractors=extractors, vulnerabilities=vulnerabilities)
    return result


if __name__ == "__main__":
    repository = filter_repository(json.load(sys.stdin))
    print("{")
    print(",\n".join(f"  {json.dumps(name)}: {json.dumps(library, separators=(',', ':'))}"
                     for name, library in repository.items()))
    print("}")
