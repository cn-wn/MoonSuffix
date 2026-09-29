# MoonSuffix design

## Invariants

`SuffixList` owns a reverse-label trie. Each node corresponds to one exact
suffix path; terminal metadata records exact, wildcard, and exception rules
together with their ICANN, PRIVATE, or unsectioned source. The trie is private
so callers cannot construct an invalid compiled list.

For every accepted domain:

1. labels are non-empty and compared after lowercasing;
2. a wildcard consumes exactly one whole label and does not imply its base;
3. any matching exception wins over non-exception matches;
4. otherwise the rule with the greatest label count wins;
5. if no eligible explicit rule matches, the selected unknown-suffix policy
   either applies the implicit `*` rule or returns `UnlistedSuffix`;
6. an exception contributes one fewer public-suffix label than its rule;
7. a registrable domain exists exactly when one label remains to the left of
   the public suffix.

These rules are direct translations of the PSL formal algorithm. Lookup never
depends on source rule order or hash-map iteration order.

## Input boundaries

The parser reads one rule per line and stops a rule at its first recognized
ASCII whitespace character (space, tab, carriage return, newline, or form feed).
Blank lines and ordinary `//` comment lines are ignored. The official ICANN and
PRIVATE begin/end markers change the section attached to subsequent rules;
nested, mismatched, and unterminated sections are rejected. `*` is valid only as
the complete leftmost label; `!` is valid only as the first character of an
exception rule. Empty labels are rejected.

The lookup API accepts a hostname, optionally ending in one root dot. It rejects
leading dots, repeated dots, and wildcard or exception syntax in hostnames.
The root dot is removed for matching and restored in textual results.

## Lookup policies

`lookup` is the compatibility-oriented browser profile: both official sections
are eligible and an unknown suffix uses the implicit wildcard. The more explicit
`lookup_with_options` supports an ICANN-only scope and a require-listed mode.
Rules outside official section markers remain eligible in either scope so small
synthetic and application-owned lists do not silently stop working. A result
reports the selected rule's section; the implicit wildcard reports no section.

`trace_lookup_with_options` is an opt-in diagnostic path over the same compiled
trie. It lists the implicit wildcard and all explicit rule memberships matching
the hostname's suffix path, including rules filtered out by ICANN-only policy.
Candidates have a stable depth/kind/section order independent of source order;
the selected candidate agrees with the ordinary lookup result. Unlike the
fast lookup path, tracing constructs evidence for every candidate. Invalid
hostname syntax fails before a trace is produced, while a valid but unlisted
hostname preserves the strict-policy failure in the trace's outcome.

## Deterministic serialization

`to_psl_text` walks the private trie, groups rules by source section, and sorts
each group lexicographically. It emits unsectioned rules first, followed by
official ICANN and PRIVATE marker blocks, with one trailing newline for every
non-empty result. Parsing that text and serializing it again produces identical
bytes and preserves lookup behavior.

The canonical form preserves rule and section semantics, not source formatting:
comments, blank lines, trailing fields, duplicate rules within one section, and
the original ordering are intentionally discarded. `snapshot` adds reproducible
metadata by hashing the canonical text's UTF-8 bytes with SHA-256 and attaching
an opaque caller-provided source revision and rule count. Its line-oriented
manifest percent-encodes the revision, preventing embedded whitespace or
delimiters from changing structure. `Snapshot::restore` is the inverse storage
boundary: it accepts only the exact four-field versioned manifest, canonical
percent-encoding and decimal forms, lowercase SHA-256 text, valid canonical PSL
bytes, and matching digest and rule count. A restored snapshot therefore has
the same invariants as one created in memory.

`bundle_text` packages that manifest and canonical PSL into one text artifact,
separated by one blank line. `restore_bundle_text` delegates to the same strict
manifest, digest, rule count, and canonical-text checks; it rejects truncated,
modified, or appended data.

The native `cmd/snapshot` command creates that artifact from a caller-supplied
local PSL and revision. It verifies the in-memory bundle before writing and
uses create-new file semantics so a second run cannot silently replace a pinned
snapshot. It does not fetch PSL data.
Its optional `--idna` mode uses the same UTS #46 adapter as library lookups;
the resulting bundle stores canonical A-label rules.

The native `cmd/lookup` command restores and verifies a bundle before parsing
its canonical rules for one lookup. It reports the manifest fields alongside
the result so a human or CI log can attribute the answer to a specific rule
set. Its optional IDNA mode normalizes the input hostname to match an A-label
bundle; strict ICANN mode rejects unknown suffixes.

The native `cmd/conformance` command accepts local PSL text or a verified
bundle and a caller-supplied `checkPublicSuffix` fixture. It runs the library's
fixture verifier, emits deterministic counts and failure CSV alongside the
canonical PSL digest, and returns a failing exit status for mismatches or
invalid input. The command does not download upstream data.

## Why the data is injected

The authoritative list changes several times per week and is separately
licensed under MPL-2.0. Embedding an unversioned snapshot would make freshness,
reproducibility, and licensing less visible. The first release therefore keeps
the engine and data lifecycle separate: callers supply text and the snapshot API
records their chosen revision and canonical digest without bundling upstream
data.

## IDNA adapter

The `idna` package converts both PSL rules and lookup hostnames to ASCII
using `moonbit-community/idna`'s UTS #46 implementation. It preserves section
markers and exact, wildcard, and exception rule prefixes. Conversion errors
identify the source rule line or input hostname. The core keeps its existing
case-only behavior for callers with already canonicalized input. IDNA adapter
lookups return A-labels, which are safe to compare and store as stable keys.

## Snapshot comparison

`Snapshot::diff` compares canonical rule identities as `(rule, section)` pairs.
It reports additions, removals, and a section move when one old membership is
replaced by exactly one new membership for the same rule. Multi-section changes
that could have more than one interpretation remain explicit additions and
removals. Rules and memberships are emitted in a fixed order, so identical
inputs produce byte-identical reports independent of hash-map iteration.

The comparison is semantic at the rule-set level. It does not claim that every
reported rule change affects a particular hostname. `Snapshot::analyze_impact`
closes that gap by evaluating an inventory under the same lookup policy before
and after an update. It classifies acceptance changes, public-suffix or
registrable-boundary changes, and prevailing-rule metadata changes. Unchanged
rows are counted but omitted; changed rows preserve the original order, index,
and duplicates. Its fully quoted CSV includes both outcomes for auditability.

The native audit command's optional IDNA mode converts raw PSL rules and both
inventories to A-labels before comparison. Verified bundle mode uses the
bundles' already-canonical rules and normalizes only the inventories. Output
uses A-labels, so reports can be compared against stored snapshot data.
When used as a gate, an empty combined inventory is an error rather than a
zero-impact success; Cookie-only inventories still count as coverage.

## Batch classification

Batch lookup preserves source order and duplicates. Each `BatchItem` contains
its zero-based input index, original text, and either a normal `Lookup` or the
same `DomainError` returned by single lookup. One malformed hostname therefore
does not discard valid rows before or after it, and summary counts make partial
failure visible.

`BatchReport::to_csv` emits a fixed schema with LF line endings and a trailing
newline. Every field uses RFC 4180-style quoting and embedded quotes are doubled,
so original inputs and diagnostic text containing commas, quotes, CR, or LF stay
inside one CSV field. Rows are never sorted: deterministic output follows the
caller's input order.

## Registrable site identity

`site_key` turns a successful lookup into a comparison key by requiring a
registrable domain and removing an optional trailing DNS root dot. Public
suffixes alone are rejected because they do not identify one independently
controlled site. The browser-style profile includes PRIVATE rules, so
`alice.github.io` and `bob.github.io` remain distinct sites; explicit policy
variants allow applications to choose a different boundary deliberately.

`same_registrable_site` compares these keys and validates the left hostname
first. It intentionally answers only the hostname portion of a site identity.
`schemeful_site` combines an HTTP(S) scheme with that key, so HTTP and HTTPS
hosts are distinct even when they share a registrable domain. It accepts
already extracted ASCII DNS hostnames, strips one root dot, and rejects invalid
schemes and hosts. Ports and paths do not enter the site key. URL parsing and
Cookie Domain acceptance remain separate concerns.

## Conformance verification

`verify_psl_test_file` consumes the line-oriented syntax used by the upstream
CC0 `tests/test_psl.txt` fixture. Blank lines and `//` comments are ignored;
every other line must be an exact `checkPublicSuffix(input, expected);` call
using `null` or an unescaped single-quoted domain. A malformed test file fails
with a source line and reason instead of silently skipping coverage.

The upstream format uses `null` for several different outcomes. MoonSuffix
accepts a rejected hostname, a public suffix without a registrable domain, or a
literal null input when null is expected, but retains those distinct actual
outcomes when a case fails. Reports preserve source order and export only
failures as fully quoted deterministic CSV.

## Policy migration audit

`analyze_policy_impact` evaluates the same ordered hostname inventory twice
against one immutable rule set. This isolates policy effects from PSL data
changes—for example, moving from browser defaults to listed ICANN suffixes
only. It reuses the same acceptance, boundary, and rule-metadata categories as
snapshot impact analysis, retains duplicates and original indexes, counts
unchanged inputs, and exports only policy-sensitive rows as deterministic CSV.
The native `cmd/policy-audit` makes this comparison usable with a pinned,
verified snapshot. It validates each inventory hostname before analysis,
optionally converts Unicode names to A-labels, reports the snapshot identity,
and can fail a deployment gate on impact or an empty inventory. Only the
lookup policy changes; PSL data remains identical on both sides.

## Cookie domain scope

`resolve_cookie_scope` implements the hostname portion of RFC 10025 cookie
storage. It canonicalizes ASCII DNS names to lowercase, removes one compatibility
leading dot from a present `Domain` attribute, and uses label-boundary domain
matching rather than a raw string suffix. A missing attribute produces a
host-only cookie. A public-suffix attribute is rejected unless it exactly equals
the request host, in which case the user-agent algorithm stores a host-only
cookie instead.

The default profile includes ICANN and PRIVATE rules because both can separate
independently controlled sites; an explicit lookup policy remains available for
specialized deployments. Request hosts may carry one trailing DNS root dot, but
a server-produced `Domain` value may not. Both inputs must already be DNS names
in ASCII/A-label form. This API does not parse URLs, IP literals, Set-Cookie
headers, Unicode IDNA input, paths, schemes, or cookie prefixes.

After a scope is resolved, `CookieScope::matches_host` checks the domain part
of delivery against another canonical ASCII request host. Host-only scopes
require equality; Domain scopes allow equality or a descendant separated by
a dot. Malformed target hosts return an error. Path, Secure, expiry, and other
Cookie attributes remain the caller's responsibility.

## Cookie scope update audit

`Snapshot::analyze_cookie_scope_impact` replays an ordered inventory of request
host and optional `Domain` attribute pairs through the Cookie scope resolver
under two pinned PSL snapshots. It classifies newly accepted and rejected
inputs, plus changes to the stored domain or host-only flag. Two rejections
remain behaviorally unchanged even if their error messages differ. Invalid
rows do not stop later rows; duplicates keep their original indexes. Changed
rows can be exported as deterministic, fully quoted CSV with a presence flag
that distinguishes a missing `Domain` attribute from an empty one. This audits
the DNS domain component of Cookie storage only, not path, scheme, expiry, or
other Cookie policy.

## Native update audit

`cmd/audit` is an I/O adapter over the portable snapshot APIs. It reads two
caller-supplied PSL files and a line-oriented hostname inventory, creates
revision-labelled snapshots, and emits one report containing summary counts,
the semantic rule diff, and the changed-hostname CSV. It never downloads or
bundles PSL data.

Inventory lines are trimmed; blank lines and trimmed lines beginning with `#`
are ignored. Every remaining hostname, including duplicates, keeps its source
order. The report is assembled only from deterministic snapshot and impact
outputs, so identical bytes, revision labels, inventory, and policy produce
identical bytes on stdout.

With `--fail-on-impact`, the command emits the same report and then exits
unsuccessfully if any inventoried hostname has changed acceptance, public
suffix, registrable boundary, or selected rule metadata. A semantic rule diff
alone does not fail the gate: the gate is intentionally scoped to the supplied
hostname inventory and chosen lookup policy.

Bundle mode first calls `Snapshot::restore_bundle_text` for each input. The
report uses the stored revisions and refuses a damaged old or candidate file
before evaluating any hostnames. Raw PSL mode remains available for exploratory
comparisons with caller-supplied revision labels.

An optional tab-separated Cookie inventory extends the same audit. A line has
one ASCII request host and optionally a second field containing the server's
`Domain` attribute. Blank lines and `#` comments are ignored, CRLF is accepted,
and extra fields or malformed DNS names are rejected with a source line number.
The hostname inventory is likewise checked against the core lookup's hostname
syntax before comparison, so a malformed name cannot silently count as an
unchanged outcome. A valid name rejected by the selected PSL policy remains a
normal audit outcome. The Cookie analysis uses the same two
verified snapshots and lookup policy as the hostname analysis. Without this
option the prior report bytes remain unchanged; with it, Cookie counts and a
changed-row CSV are appended. `--fail-on-impact` then considers both hostname
and Cookie changes, allowing an unchanged host inventory to expose a Cookie
storage regression.

## Complexity

Parsing is linear in the total number of labels inserted, aside from hash-map
operations. A lookup walks at most one trie edge per hostname label and performs
constant work at each node. Joining the selected suffix labels is linear in the
returned text size.
