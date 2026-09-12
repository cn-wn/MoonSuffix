# Ecosystem position

Checked on 2026-09-11 with the Mooncakes registry and public repositories.

## Classification

MoonSuffix is a complementary missing layer, not a new URL parser or IDNA
implementation.

Using `moon 0.1.20260904`, the commands `moon search public-suffix`,
`moon search psl`, `moon search etld`, and `moon search suffix` found no MoonBit
package whose public boundary is PSL parsing and registrable-domain lookup. The
broad `suffix` search returned suffix-array and unrelated packages. This is a
time-bounded registry check, not a claim of permanent ecosystem uniqueness.

## Adjacent projects

- [`tonyfettes/url`](https://mooncakes.io/docs/tonyfettes/url) implements the
  WHATWG URL Standard, including URL-host parsing and IDNA-related behavior.
- [`moonbit-community/unicode`](https://mooncakes.io/docs/moonbit-community/unicode)
  provides maintained Unicode and IDNA facilities.
MoonSuffix supplies the registry-control boundary that these higher- and
lower-level components can consume. Its target users are HTTP frameworks,
Cookie/session implementations, crawlers, security tools, and domain analytics.

## Rejected first idea

An IPv4/CIDR toolkit was rejected before implementation because the registry
already contains `bobzhang/ipaddr`, `lzh123411/mooncidr`, and
`BeiLaDuo/cidr-audit`. Their combined boundary covers address parsing, CIDR
matching/ranges, and policy auditing, so another foundational rewrite would not
have had an honest independent value.

- [`bobzhang/ipaddr`](https://mooncakes.io/docs/bobzhang/ipaddr)
- [`lzh123411/mooncidr`](https://mooncakes.io/docs/lzh123411/mooncidr)
- [`BeiLaDuo/cidr-audit`](https://mooncakes.io/docs/BeiLaDuo/cidr-audit)
