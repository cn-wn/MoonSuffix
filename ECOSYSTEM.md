# Ecosystem position

Checked on 2026-09-14 with the Mooncakes registry and public repositories.

## Classification

MoonSuffix partially overlaps one browser-internal PSL helper, but remains a
complementary data-lifecycle layer rather than another URL parser, IDNA library,
or Cookie jar.

`moon search publicsuffix` and `moon search "registrable domain"` identify
[`mizchi/crater-browser-http`](https://mooncakes.io/docs/mizchi/crater-browser-http).
Its public `psl` subpackage reduces hostnames for Crater's Cookie and SameSite
implementation. The source documents a hand-curated rule subset with a
last-two-label fallback; its currently bundled wildcard and exception arrays
are empty.

MoonSuffix deliberately owns a different boundary: callers can inject a full
or application-specific PSL, select ICANN versus PRIVATE semantics, inspect the
prevailing rule, serialize canonical rule sets, verify stored snapshots, report
semantic rule changes, and measure their impact on a hostname inventory. Its
independent value is reproducible PSL data management and impact auditing.

- [Crater PSL implementation](https://github.com/mizchi/crater/tree/main/http/psl)
- [Crater SameSite integration](https://github.com/mizchi/crater/tree/main/http/samesite)

## Adjacent projects

- [`tonyfettes/url`](https://mooncakes.io/docs/tonyfettes/url) and
  [`connect0459/urllib`](https://mooncakes.io/docs/connect0459/urllib) implement
  URL and host parsing. They are natural sources of already-extracted hostnames.
- [`moonbit-community/idna`](https://mooncakes.io/docs/moonbit-community/idna),
  [`tonyfettes/idna`](https://mooncakes.io/docs/tonyfettes/idna), and
  [`ZSeanYves/MoonIDNA`](https://mooncakes.io/docs/ZSeanYves/MoonIDNA) provide
  UTS #46 / IDNA facilities. MoonSuffix expects callers to normalize list rules
  and hostnames into the same representation until an adapter is implemented.

Mooncakes searches for `moonsuffix`, `tld`, and `effective-tld` found no second
standalone package with the same full-PSL lifecycle boundary. This is a dated
collision check, not a permanent uniqueness claim.

## Rejected first idea

An IPv4/CIDR toolkit was rejected before implementation because the registry
already contains `bobzhang/ipaddr`, `lzh123411/mooncidr`, and
`BeiLaDuo/cidr-audit`. Their combined boundary covers address parsing, CIDR
matching/ranges, and policy auditing, so another foundational rewrite would not
have had an honest independent value.

- [`bobzhang/ipaddr`](https://mooncakes.io/docs/bobzhang/ipaddr)
- [`lzh123411/mooncidr`](https://mooncakes.io/docs/lzh123411/mooncidr)
- [`BeiLaDuo/cidr-audit`](https://mooncakes.io/docs/BeiLaDuo/cidr-audit)
