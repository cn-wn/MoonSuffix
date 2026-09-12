# MoonSuffix

MoonSuffix is a pure MoonBit Public Suffix List rule-selection engine for
answering two deceptively difficult questions about a hostname:

- What is its public suffix?
- What is the registrable domain (often called eTLD+1)?

It parses caller-supplied [Public Suffix List](https://publicsuffix.org/) text,
implements exact, wildcard, exception, longest-rule, and implicit `*` behavior,
and returns an explainable match. The reusable core has no file-system or
network dependency and is designed for MoonBit's Wasm, Wasm-GC, and JavaScript
targets.

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

Run the included example:

```text
moon run cmd/main
```

## Current API

- `SuffixList::parse` compiles PSL text into a reverse-label trie.
- `lookup` returns the case-normalized domain, public suffix, optional registrable
  domain, prevailing rule, and rule kind.
- `public_suffix`, `registrable_domain`, and `is_public_suffix` provide focused
  convenience queries.
- Rules may be exact (`co.uk`), wildcard (`*.ck`), or exception (`!www.ck`).
- Unknown suffixes use the PSL algorithm's implicit `*` rule.
- A single trailing root dot is preserved in returned domain strings.

## Deliberate v0.1 boundaries

- No PSL snapshot is bundled. Applications inject a pinned or freshly fetched
  list, so data freshness and MPL-2.0 obligations remain explicit.
- Inputs and list rules are lowercased, but MoonSuffix does not yet convert
  between Unicode U-labels and Punycode A-labels. Callers must canonicalize both
  to the same representation before parsing and lookup.
- ICANN and PRIVATE section markers are currently treated alike. This matches
  common browser-style lookups, but an ICANN-only policy is not implemented yet.
- Callers must extract a hostname before lookup; URLs and IP literals are outside
  this API's input contract.

## Roadmap

1. Add explicit ICANN-only/all-sections and require-listed/default-wildcard
   policies.
2. Add an adapter for the maintained MoonBit UTS #46 / IDNA implementation and
   run the complete upstream Unicode/Punycode conformance cases.
3. Add deterministic trie serialization and a reproducible snapshot generator.
4. Add batch classification, update diffs, and Cookie/same-site integration
   examples.

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
