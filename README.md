# MoonSuffix

MoonSuffix is a pure MoonBit Public Suffix List rule-selection engine for
answering two deceptively difficult questions about a hostname:

- What is its public suffix?
- What is the registrable domain (often called eTLD+1)?

It parses caller-supplied [Public Suffix List](https://publicsuffix.org/) text,
implements exact, wildcard, exception, longest-rule, and implicit `*` behavior,
recognizes the official ICANN and PRIVATE sections, and returns an explainable
match. The reusable core has no file-system or network dependency and is
designed for MoonBit's Wasm, Wasm-GC, JavaScript, and native targets.

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

For Unicode hostnames, use the separate IDNA adapter so PSL rules and input
hostnames are converted to the same A-label form:

```moonbit
let list = @suffix_idna.parse_psl("公司.cn\ncom\n").unwrap()
let result = @suffix_idna.lookup(list, "商店.公司.cn").unwrap()
println(result.public_suffix()) // xn--55qx5d.cn
println(result.registrable_domain().unwrap()) // xn--czrs0t.xn--55qx5d.cn
```

Run this example with `moon run examples/idna`. Import
`cn-wn/moonsuffix/idna` as `suffix_idna`; it depends on
`moonbit-community/idna`. The core package remains usable without importing
that adapter.

For a Unicode hostname collection, the adapter's batch API keeps invalid
inputs as rows and continues with later names:

```moonbit
let report = @suffix_idna.lookup_batch(
  list,
  ["商店.公司.cn", "商店..公司.cn", "xn--czrs0t.xn--55qx5d.cn"],
)
println(report.to_csv())
```

The same adapter also accepts Unicode Cookie request hosts and `Domain`
attributes. It converts both names to A-labels before applying the core's
public-suffix and domain-match rules:

```moonbit
let scope = @suffix_idna.resolve_cookie_scope(
  list, "api.商店.公司.cn", Some(".商店.公司.cn"),
).unwrap()
println(scope.domain()) // xn--czrs0t.xn--55qx5d.cn
println(@suffix_idna.cookie_scope_matches_host(scope, "别的.商店.公司.cn")) // Ok(true)
```

`shareable_cookie_scopes` is available from the IDNA adapter too. These APIs
cover Cookie domain scope and matching, not path, Secure, expiry, or a complete
Cookie jar.

For HTTP site comparisons, pass already extracted scheme and ASCII hostname:

```moonbit
let first = suffixes.schemeful_site("https", "shop.example.com").unwrap()
let second = suffixes.schemeful_site("https", "api.example.com").unwrap()
let third = suffixes.schemeful_site("http", "api.example.com").unwrap()
println(first.same_site(second)) // true
println(first.same_site(third))  // false
```

To find the `Domain` values a server may use to share a Cookie with sibling
hosts, ask the same PSL-aware core for scopes ordered from narrowest to
broadest:

```moonbit
let scopes = suffixes.shareable_cookie_scopes("api.shop.example.com").unwrap()
for scope in scopes {
  println(scope.domain())
}
```

This prints `api.shop.example.com`, `shop.example.com`, then `example.com`.

The public suffix (`com` here) is never suggested. For a host that is itself a
public suffix, the result is empty; an explicit equal `Domain` attribute would
create a host-only Cookie, not a shareable one. Inputs must be ASCII/A-label
DNS names; callers with Unicode names can first use the separate IDNA adapter.

## Build a PSL snapshot

Build a single-file snapshot from an explicitly chosen local PSL revision:

```text
moon run --target native cmd/snapshot \
  examples/audit/old.psl \
  old.snapshot \
  --revision example-v1
```

The output includes canonical rules, revision, SHA-256 and rule count. The
command verifies its own bundle before writing and refuses to replace an
existing output file.

For a Unicode PSL source, pass `--idna`; the stored canonical rules use
A-labels. For example:

```text
moon run --target native cmd/snapshot \
  examples/idna/rules.psl unicode.snapshot \
  --revision unicode-example-v1 --idna
```

Query a stored snapshot directly:

```text
moon run --target native cmd/lookup \
  unicode.snapshot 商店.公司.cn --idna --strict-icann
```

The command verifies the bundle and prints its revision, digest, selected
public suffix, registrable domain, and prevailing rule. Unicode input requires
an A-label snapshot built with `--idna`.

## Check PSL conformance cases

Run caller-supplied `checkPublicSuffix` cases against a local PSL file:

```text
moon run --target native cmd/conformance \
  examples/conformance/rules.psl examples/conformance/cases.txt
```

The command prints the rule-set digest, case counts, and a CSV failure list.
It exits unsuccessfully if a case fails, the fixture is empty or malformed, or
the rules cannot be parsed. Use `--bundle` when the first input is a verified
snapshot bundle. The included cases are small, synthetic examples, not a claim
of passing the full upstream PSL suite; supply your own pinned PSL and test
revision for a broader compatibility check.

## Audit a PSL update

The native audit command compares a deployed PSL with a candidate list, then
evaluates an ordered hostname inventory against both snapshots:

```text
moon run --target native cmd/audit \
  examples/audit/old.psl \
  examples/audit/new.psl \
  examples/audit/hosts.txt \
  --from example-v1 \
  --to example-v2 \
  --strict-icann
```

It writes one deterministic report containing snapshot revisions and digests,
semantic rule changes, summary counts, and CSV rows for hostnames whose lookup
outcome changed. Blank inventory lines and lines beginning with `#` are ignored;
remaining lines preserve their order and duplicates. The command only reads
local files and does not fetch or redistribute PSL data.

To audit pinned bundles, build an old and candidate snapshot with
`cmd/snapshot`, then run:

```text
moon run --target native cmd/audit \
  old.snapshot new.snapshot examples/audit/hosts.txt \
  --bundles --strict-icann --fail-on-impact
```

Bundle mode verifies both files before comparing them and reads revision labels
from their manifests. The `--from` and `--to` options apply only to raw PSL
inputs.

Add `--fail-on-impact` to use it as an upgrade gate in CI. It still prints the
full report, then exits unsuccessfully if any hostname in the inventory has a
changed lookup outcome. A rule-only change with no effect on the supplied
inventory passes; maintain an inventory representative of your deployment.
The gate also fails when both the hostname and optional Cookie inventories are
empty, because such a run has checked no outcomes. A Cookie-only inventory is
valid when supplied intentionally.

To audit Cookie storage as well, add a Cookie inventory. Each non-comment line
contains an ASCII request host by default; an optional tab and second field specify the
Cookie `Domain` attribute. A one-field line means that attribute is absent.
For example, this invocation keeps the hostname inventory unchanged but finds
three Cookie-scope changes and fails the upgrade gate:

```text
moon run --target native cmd/audit \
  examples/audit/old.psl examples/audit/new.psl \
  examples/audit/stable-hosts.txt \
  --from example-v1 --to example-v2 --strict-icann \
  --cookie-inventory examples/audit/cookies.tsv --fail-on-impact
```

The report adds Cookie counts and changed-row CSV only when the option is
present. The gate fails if either a hostname or Cookie scope changes. These
inputs cover the DNS domain component of Cookie storage, not path, expiry, or
Secure. Without `--idna`, prepare Unicode names as A-labels before using this inventory. Hostnames
rejected by the core lookup syntax and malformed ASCII Cookie DNS fields fail
with their source line instead of being silently counted as unchanged.

For Unicode PSL rules and DNS names in either inventory, add `--idna`. The
command converts raw rules, request hosts, Cookie Domain attributes, and
hostname inventory entries to A-labels before comparison. In `--bundles`
mode, the bundles must already contain A-label rules (for example, built with
`cmd/snapshot --idna`); the flag normalizes only inventory names. Report rows
show the normalized A-labels.

```text
moon run --target native cmd/audit \
  examples/audit/old-unicode.psl examples/audit/new-unicode.psl \
  examples/audit/unicode-hosts.txt \
  --from old --to new --idna --strict-icann \
  --cookie-inventory examples/audit/unicode-cookies.tsv --fail-on-impact
```

This synthetic update changes both the registrable-domain boundary for the
hostname and whether the Cookie Domain is a public suffix, so the gate exits
unsuccessfully.

## Audit a lookup-policy migration

The native `cmd/policy-audit` command checks a different kind of change: it
holds one verified PSL snapshot fixed and compares browser-default lookup with
strict ICANN lookup over your hostname inventory. This exposes, for example,
hosts affected by ignoring PRIVATE rules or rejecting unlisted suffixes.

```text
moon run --target native cmd/snapshot \
  examples/audit/old.psl old.snapshot --revision example-v1
moon run --target native cmd/policy-audit \
  old.snapshot examples/audit/hosts.txt --fail-on-impact
```

The second command prints a deterministic summary and changed-row CSV, then
exits unsuccessfully when an outcome changes or the inventory is empty. It
preserves input order and duplicates; malformed hostnames fail with their
source line. Add `--idna` for Unicode inventory names, provided the snapshot
was built with A-label rules (for example, `cmd/snapshot --idna`). No PSL data
is fetched by either command.

## Classify a hostname inventory

`cmd/classify` applies one verified snapshot to a line-oriented hostname file
and prints a CSV row for every non-comment entry. A bad hostname stays in the
output as an error row; later entries are still processed.

```text
moon run --target native cmd/snapshot \
  examples/audit/old.psl classify.snapshot --revision example-v1
moon run --target native cmd/classify \
  classify.snapshot examples/classify/hosts.txt --strict-icann
```

The report includes the snapshot revision and digest, policy, and success/error
counts. Add `--fail-on-error` to return an unsuccessful status after printing
the report if any row failed or the inventory is empty. Blank and `#` comment
lines are ignored; remaining entries retain their order and duplicates, with
zero-based CSV indexes. By default, supply ASCII or pre-normalized A-label
hostnames. For Unicode input, use `--idna` with a snapshot built from
IDNA-normalized PSL rules:

```text
moon run --target native cmd/snapshot \
  examples/idna/rules.psl unicode.snapshot \
  --revision unicode-example-v1 --idna
moon run --target native cmd/classify \
  unicode.snapshot examples/classify/unicode-hosts.txt \
  --idna --strict-icann
```

The IDNA mode keeps the original input in the CSV and records its A-label form
in `normalized_domain`. IDNA conversion failures become error rows instead of
aborting the inventory.

## Check rule coverage in a hostname sample

The portable core can count how often each explicit PSL rule is actually
selected by an application-supplied hostname sample:

```moonbit
let coverage = suffixes.analyze_rule_coverage(
  ["api.example.com", "www.www.ck", "service.internal"],
  @moonsuffix.LookupOptions::browser_default(),
)
println(coverage.observed_rule_count())
println(coverage.to_csv())
```

The report includes every rule and section membership, even those selected
zero times, and separates implicit-wildcard lookups from invalid or unlisted
hosts. It is useful for checking whether a test or production sample exercises
the rules you care about. A zero count means only “not observed in this
sample”; it is not proof that a PSL rule is unnecessary.

## Current API

- `SuffixList::parse` compiles PSL text into a reverse-label trie.
- `lookup` returns the case-normalized domain, public suffix, optional registrable
  domain, prevailing rule, rule kind, and source section. It keeps browser-style
  behavior by considering both ICANN and PRIVATE rules and falling back to `*`.
- `lookup_with_options` supports ICANN-only or all-section matching and either
  an implicit wildcard or an error for unknown suffixes.
- `trace_lookup_with_options` exposes every matching rule candidate, its source
  section, policy eligibility, and whether it won. A valid but unlisted host
  retains the strict-policy error alongside the trace.
- `to_psl_text` exports a deterministic, parseable representation for pinned
  snapshots, hashing, and reproducible builds.
- `snapshot` binds canonical PSL text to an opaque source revision, a SHA-256
  digest, its rule count, and a deterministic line-oriented manifest.
- `Snapshot::restore` verifies stored canonical PSL text against every manifest
  field before reconstructing a trusted snapshot.
- `Snapshot::bundle_text` and `restore_bundle_text` store the manifest and
  canonical rules in one strictly verified text artifact.
- `cmd/snapshot` builds a single-file snapshot from a local PSL source and an
  explicit revision without overwriting existing output. Its `--idna` mode
  normalizes Unicode rules to A-labels first.
- `cmd/lookup` verifies a stored snapshot before classifying one hostname,
  with optional IDNA and strict ICANN lookup policies.
- `Snapshot::diff` produces deterministic additions, removals, and unambiguous
  ICANN/PRIVATE section moves between two snapshots.
- `Snapshot::analyze_impact` evaluates a hostname inventory against old and new
  snapshots, classifies only changed outcomes, and exports deterministic CSV.
- `analyze_policy_impact` compares two lookup policies over one hostname
  inventory, exposing domains affected by a stricter deployment policy.
- `analyze_rule_coverage` counts selected explicit rules by section and
  distinguishes implicit, unlisted, and invalid inputs in a deterministic CSV.
- `lookup_batch` and `lookup_batch_with_options` preserve input order and retain
  invalid hostnames as row-level errors; `BatchReport::to_csv` exports every row.
- `site_key` and `same_registrable_site` expose canonical registrable-hostname
  boundaries for Cookie policy and hostname-level same-site integration.
- `schemeful_site` creates an HTTP(S) site identity from an ASCII hostname and
  compares both scheme and registrable domain, including PRIVATE PSL rules.
- `resolve_cookie_scope` converts an optional Cookie `Domain` attribute into its
  canonical stored domain and host-only flag, rejecting public-suffix scope
  escalation, unrelated domains, and malformed non-ASCII server values.
- `shareable_cookie_scopes` enumerates valid `Domain` Cookie scopes from the
  request host down to its registrable boundary under the selected PSL policy.
- `CookieScope::matches_host` checks whether that stored domain scope covers a
  later request hostname, distinguishing host-only and Domain cookies.
- `Snapshot::analyze_cookie_scope_impact` tests an ordered inventory of request
  hosts and Cookie `Domain` attributes against old and candidate PSL snapshots,
  reporting changed acceptance or stored scopes as deterministic CSV.
- `CookieScopeInput::validate_syntax` checks ASCII request-host and `Domain`
  syntax independently of PSL policy, for fail-closed inventory ingestion.
- `cmd/audit` joins snapshots, semantic rule diffs, and hostname impact analysis
  into a native, local-file workflow with deterministic text and CSV output.
  It can verify stored bundles and audit an optional Cookie inventory;
  `--fail-on-impact` can block a candidate update in CI.
- `cmd/policy-audit` compares browser-default and strict ICANN lookup against
  one verified snapshot and can gate a policy migration in CI.
- `cmd/classify` turns a hostname inventory into ordered batch-lookup CSV,
  preserving row-level errors and optionally failing a CI input-quality gate.
- `idna` converts Unicode PSL rules and hostnames with UTS #46 before querying
  the core; returned domain strings are A-labels. Its batch API preserves
  Unicode inputs and IDNA errors as ordered rows with deterministic CSV. It
  also resolves Unicode Cookie scopes and matches later Unicode request hosts.
- `verify_psl_test_file` runs upstream-style `checkPublicSuffix` cases, retains
  ordered mismatch diagnostics, and exports failures as deterministic CSV.
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
- The core lowercases rules and hostnames but does not perform IDNA conversion.
  Use the separate `idna` adapter for Unicode input; its results are ASCII
  A-labels and do not preserve the original display spelling.
- Callers must extract a hostname before lookup; URLs and IP literals are outside
  this API's input contract.

## Roadmap

1. Add a reproducible static PSL build path and benchmark lookup and startup.

## Validation

```text
moon fmt
moon info
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
moon test --target wasm-gc --deny-warn
moon test --target js --deny-warn
moon run cmd/main
moon run examples/idna
moon check cmd/audit --target native --deny-warn
moon test cmd/audit --target native --deny-warn
moon check cmd/snapshot --target native --deny-warn
moon test cmd/snapshot --target native --deny-warn
moon check cmd/lookup --target native --deny-warn
moon test cmd/lookup --target native --deny-warn
moon check cmd/conformance --target native --deny-warn
moon test cmd/conformance --target native --deny-warn
moon check cmd/policy-audit --target native --deny-warn
moon test cmd/policy-audit --target native --deny-warn
moon check cmd/classify --target native --deny-warn
moon test cmd/classify --target native --deny-warn
```

See [DESIGN.md](DESIGN.md), [ECOSYSTEM.md](ECOSYSTEM.md), and
[SOURCES.md](SOURCES.md) for design boundaries and evidence.

## License

MoonSuffix source code is licensed under Apache-2.0. No copy of the PSL data is
distributed in this repository. The upstream list has its own MPL-2.0 license;
the upstream conformance test is dedicated to the public domain under CC0.
