# Offline advisory snapshots

## RustSec

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

## Retire.js

[`retirejs.json`](retirejs.json) is a filtered copy of Retire.js
[`repository/jsrepository.json`](https://raw.githubusercontent.com/RetireJS/retire.js/0a997046b9a38c073dea8c864b015e515fc677ec/repository/jsrepository.json)
at commit `0a997046b9a38c073dea8c864b015e515fc677ec`, dated 2026-11-11.
The upstream file has SHA-256 `829ac69ca802668081d260293a99d71039a481bf052e12f10beca135dfa0fbe8`.
The upstream [LICENSE.md](https://github.com/RetireJS/retire.js/blob/0a997046b9a38c073dea8c864b015e515fc677ec/LICENSE.md)
is Apache-2.0 and is bundled as [Apache-2.0.txt](LICENSES/Apache-2.0.txt).

The snapshot keeps filename and URI extractors and advisory bounds, severity and
identifiers. It drops the synthetic example, entries without usable extractors or
advisories, and descriptive text. String and list identifiers share a list format.
X03-01 reads this bundled snapshot during evaluation.

Generate and test the filtered data from a local copy of the pinned source:

```sh
python3 fixtures/advisories/generate_retire.py < /path/to/jsrepository.json > /tmp/retirejs.json
python3 -B -m unittest discover -s fixtures/advisories -p test_generate_retire.py
```

Review the diff before replacing `retirejs.json`, update the provenance here,
and run `cargo test --locked javascript` against the new snapshot.
