# MoonSuffix

MoonSuffix is a pure MoonBit Public Suffix List rule-selection engine for
answering two deceptively difficult questions about a hostname:

- What is its public suffix?
- What is the registrable domain (often called eTLD+1)?

It parses caller-supplied [Public Suffix List](https://publicsuffix.org/) text,
implements exact, wildcard, exception, longest-rule, and implicit `*` behavior,
recognizes the official ICANN and PRIVATE sections, and returns an explainable
match. The reusable core has no file-system or network dependency and is
designed for MoonBit's Wasm, Wasm-GC, and JavaScript targets.

## Why this project exists

URL parsing tells an application where the hostname is; it does not tell the
application which labels are controlled by a registry. That boundary matters
for Cookie policy, same-site decisions, crawler deduplication, certificate
tooling, and domain analytics.

MoonSuffix is complementary to MoonBit's existing URL and IDNA libraries. It
does not parse URLs, perform DNS, or replace UTS #46 canonicalization.

## Quick start

```moonbit
let rules =
  #|com
  #|co.uk
  #|*.ck
  #|!www.ck

let suffixes = @moonsuffix.SuffixList::parse(rules).unwrap()
let result = suffixes.lookup("api.shop.example.co.uk").unwrap()

println(result.public_suffix())       // co.uk
println(result.registrable_domain())  // Some(example.co.uk)
println(result.matched_rule())        // co.uk
```

Applications that must reject privately managed or unknown suffixes can select
an explicit policy:

```moonbit
let result = suffixes.lookup_with_options(
  "api.example.com",
  @moonsuffix.LookupOptions::strict_icann(),
).unwrap()
```

Run the included example:

```text
moon run cmd/main
```

## Current API

- `SuffixList::parse` compiles PSL text into a reverse-label trie.
- `lookup` returns the case-normalized domain, public suffix, optional registrable
  domain, prevailing rule, rule kind, and source section. It keeps browser-style
  behavior by considering both ICANN and PRIVATE rules and falling back to `*`.
- `lookup_with_options` supports ICANN-only or all-section matching and either
  an implicit wildcard or an error for unknown suffixes.
- `to_psl_text` exports a deterministic, parseable representation for pinned
  snapshots, hashing, and reproducible builds.
- `snapshot` binds canonical PSL text to an opaque source revision, a SHA-256
  digest, its rule count, and a deterministic line-oriented manifest.
- `Snapshot::diff` produces deterministic additions, removals, and unambiguous
  ICANN/PRIVATE section moves between two snapshots.
- `Snapshot::analyze_impact` evaluates a hostname inventory against old and new
  snapshots, classifies only changed outcomes, and exports deterministic CSV.
- `lookup_batch` and `lookup_batch_with_options` preserve input order and retain
  invalid hostnames as row-level errors; `BatchReport::to_csv` exports every row.
- `site_key` and `same_registrable_site` expose canonical registrable-hostname
  boundaries for Cookie policy and hostname-level same-site integration.
- `public_suffix`, `registrable_domain`, and `is_public_suffix` provide focused
  convenience queries.
- Rules may be exact (`co.uk`), wildcard (`*.ck`), or exception (`!www.ck`).
- Unknown suffixes use the PSL algorithm's implicit `*` rule.
- A single trailing root dot is preserved in returned domain strings.

## Deliberate v0.1 boundaries

- No PSL snapshot is bundled. Applications inject a pinned or freshly fetched
  list, so data freshness and MPL-2.0 obligations remain explicit.
- Snapshot revision labels are supplied by the caller. SHA-256 detects canonical
  content changes but does not authenticate the source or fetch upstream data.
- Inputs and list rules are lowercased, but MoonSuffix does not yet convert
  between Unicode U-labels and Punycode A-labels. Callers must canonicalize both
  to the same representation before parsing and lookup.
- Callers must extract a hostname before lookup; URLs and IP literals are outside
  this API's input contract.

## Roadmap

1. Add an adapter for the maintained MoonBit UTS #46 / IDNA implementation and
   run the complete upstream Unicode/Punycode conformance cases.
2. Add URL adapters for schemeful same-site and Cookie Domain validation.

## Validation

```text
moon fmt
moon info
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
moon test --target wasm-gc --deny-warn
moon test --target js --deny-warn
moon run cmd/main
```

See [DESIGN.md](DESIGN.md), [ECOSYSTEM.md](ECOSYSTEM.md), and
[SOURCES.md](SOURCES.md) for design boundaries and evidence.

## License

MoonSuffix source code is licensed under Apache-2.0. No copy of the PSL data is
distributed in this repository. The upstream list has its own MPL-2.0 license;
the upstream conformance test is dedicated to the public domain under CC0.
