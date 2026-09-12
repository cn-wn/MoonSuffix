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

## Why the data is injected

The authoritative list changes several times per week and is separately
licensed under MPL-2.0. Embedding an unversioned snapshot would make freshness,
reproducibility, and licensing less visible. The first release therefore keeps
the engine and data lifecycle separate: callers supply text, while future
tooling will pin the upstream revision and record its digest.

## Complexity

Parsing is linear in the total number of labels inserted, aside from hash-map
operations. A lookup walks at most one trie edge per hostname label and performs
constant work at each node. Joining the selected suffix labels is linear in the
returned text size.
