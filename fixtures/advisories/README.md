# Offline RustSec snapshot

The data comes from the crates.io advisories in the [RustSec Advisory Database](https://github.com/RustSec/advisory-db/tree/f291af9b1cc0d21dfcea1709d6b037963cef262b/crates)
at commit `f291af9b1cc0d21dfcea1709d6b037963cef262b` dated 2026-11-20.
The snapshot retains vulnerability and unmaintained advisory IDs, version ranges,
and withdrawal status. The two rules evaluate the public crates.io registry.
The local snapshot date is displayed with the results. The app does not query
any registry or advisory service during a scan.

To refresh the data from a trusted checkout, run
`python3 fixtures/advisories/generate.py /path/to/advisory-db > /tmp/rustscope-rustsec.json`
and review the generated changes before replacing `rustsec.json`. Update the
commit and date here and run the dependency tests against the updated snapshot.

See [LICENSE.txt](LICENSE.txt) for the upstream data terms and the
`attributions` field for GitHub Security Advisory attribution.
