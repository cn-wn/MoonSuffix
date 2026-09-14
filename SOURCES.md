# Sources and provenance

MoonSuffix's implementation is original code based on public specifications.
No source code or PSL data is copied into this repository.

## Normative behavior

- [Public Suffix List format and formal algorithm](https://github.com/publicsuffix/list/wiki/Format)
- [Authoritative Public Suffix List download](https://publicsuffix.org/list/public_suffix_list.dat)
- [Public Suffix List project](https://github.com/publicsuffix/list)
- [NIST FIPS 180-4 Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

The authoritative `public_suffix_list.dat` is licensed under MPL-2.0. It is not
bundled here. Applications that vendor or redistribute that data, or distribute
a derived snapshot, should follow MPL-2.0 and retain the applicable upstream
notices.

The private SHA-256 implementation used for snapshot digests follows FIPS
180-4. Its tests include the standard empty, short, and multi-block message
vectors; no cryptographic implementation source code was copied.

## Tests

Selected semantic scenarios in `moonsuffix_test.mbt` are adapted into MoonBit
assertions from the upstream
[`tests/test_psl.txt`](https://github.com/publicsuffix/list/blob/main/tests/test_psl.txt),
whose header dedicates its copyright to the public domain under CC0 1.0. Tests
also use small synthetic rule sets written for MoonSuffix to isolate invariants.
The `verify_psl_test_file` API parses that fixture's call syntax so users can
run independently obtained upstream cases without bundling them in this module.
