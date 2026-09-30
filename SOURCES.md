# Sources and provenance

MoonSuffix's implementation is original code based on public specifications.
No source code or PSL data is copied into this repository.

## Normative behavior

- [Public Suffix List format and formal algorithm](https://github.com/publicsuffix/list/wiki/Format)
- [Authoritative Public Suffix List download](https://publicsuffix.org/list/public_suffix_list.dat)
- [Public Suffix List project](https://github.com/publicsuffix/list)
- [NIST FIPS 180-4 Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [RFC 10025: Cookies: HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc10025.html)

The authoritative `public_suffix_list.dat` is licensed under MPL-2.0. It is not
bundled here. Applications that vendor or redistribute that data, or distribute
a derived snapshot, should follow MPL-2.0 and retain the applicable upstream
notices.

The private SHA-256 implementation used for snapshot digests follows FIPS
180-4. Its tests include the standard empty, short, and multi-block message
vectors; no cryptographic implementation source code was copied.

The optional `idna` adapter depends on
[`moonbit-community/idna`](https://mooncakes.io/docs/moonbit-community/idna)
(Apache-2.0) for UTS #46 conversion. MoonSuffix does not copy its source or
Unicode data tables.

## Tests

Selected semantic scenarios in `moonsuffix_test.mbt` are adapted into MoonBit
assertions from the upstream
[`tests/test_psl.txt`](https://github.com/publicsuffix/list/blob/main/tests/test_psl.txt),
whose header dedicates its copyright to the public domain under CC0 1.0. Tests
also use small synthetic rule sets written for MoonSuffix to isolate invariants.
The `verify_psl_test_file` API parses that fixture's call syntax so users can
run independently obtained upstream cases without bundling them in this module.

CI verifies the full upstream PSL and test file from publicsuffix/list commit
`a179a48c465e818cfd8d626691cb317985da87fb`. It checks the downloaded
files against SHA-256 values before running `cmd/conformance --idna`:

- `public_suffix_list.dat`: `7333192f818588d9d0044d27d67210c782acd6d87cf71f54a00dfa20a561cfc9`
- `tests/test_psl.txt`: `8f50ad958916d6a8f79fba2363501475571acce752757f9126fe9d2f17dd920d`

The source PSL is MPL-2.0 and the upstream test fixture is CC0. CI downloads
them at test time; this repository does not redistribute either file. The
result is a pinned compatibility check, not a guarantee for later PSL revisions.
