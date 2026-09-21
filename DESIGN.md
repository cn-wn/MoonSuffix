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

## Why the data is injected

The authoritative list changes several times per week and is separately
licensed under MPL-2.0. Embedding an unversioned snapshot would make freshness,
reproducibility, and licensing less visible. The first release therefore keeps
the engine and data lifecycle separate: callers supply text and the snapshot API
records their chosen revision and canonical digest without bundling upstream
data.

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
Applications implementing schemeful same-site behavior must parse and compare
URL schemes separately, and Cookie Domain acceptance requires additional RFC
6265 domain-matching rules.

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

## Complexity

Parsing is linear in the total number of labels inserted, aside from hash-map
operations. A lookup walks at most one trie edge per hostname label and performs
constant work at each node. Joining the selected suffix labels is linear in the
returned text size.
