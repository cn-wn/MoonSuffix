///|
fn official_semantics_fixture() -> SuffixList {
  SuffixList::parse(
    (
      #|// compact fixture derived from the upstream CC0 semantic cases
      #|biz
      #|com
      #|uk.com
      #|ac
      #|*.mm
      #|jp
      #|ac.jp
      #|kyoto.jp
      #|ide.kyoto.jp
      #|*.kobe.jp
      #|!city.kobe.jp
      #|*.ck
      #|!www.ck
      #|公司.cn
      #|
    ),
  ).unwrap()
}

///|
fn sectioned_fixture() -> SuffixList {
  SuffixList::parse(
    (
      #|// ===BEGIN ICANN DOMAINS===
      #|com
      #|io
      #|// ===END ICANN DOMAINS===
      #|// ===BEGIN PRIVATE DOMAINS===
      #|github.io
      #|// ===END PRIVATE DOMAINS===
      #|
    ),
  ).unwrap()
}

///|
test "parse comments whitespace and duplicate rules deterministically" {
  let suffixes = SuffixList::parse(
    (
      #| // comment
      #|com trailing-comment
      #|org	owner
      #|com
      #|
    ),
  ).unwrap()
  assert_eq(suffixes.rule_count(), 2)
  assert_eq(suffixes.node_count(), 3)
}

///|
test "reject malformed rule syntax and recover on the next parse" {
  assert_true(SuffixList::parse("foo.*.com") is Err(_))
  assert_true(SuffixList::parse("*foo.com") is Err(_))
  assert_true(SuffixList::parse(".com") is Err(_))
  assert_true(SuffixList::parse("!") is Err(_))
  let valid = SuffixList::parse("com").unwrap()
  assert_eq(valid.public_suffix("www.example.com").unwrap(), "com")
}

///|
test "parse PSL section markers strictly and recover after errors" {
  assert_true(
    SuffixList::parse(
      "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END PRIVATE DOMAINS===",
    )
    is Err(_),
  )
  assert_true(
    SuffixList::parse(
      "// ===BEGIN ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===",
    )
    is Err(_),
  )
  assert_true(
    SuffixList::parse("// ===BEGIN PRIVATE DOMAINS===\ngithub.io") is Err(_),
  )
  let valid = sectioned_fixture()
  assert_eq(valid.rule_count(), 3)
}

///|
test "browser and ICANN-only scopes select different prevailing rules" {
  let suffixes = sectioned_fixture()
  let browser = suffixes.lookup("user.github.io").unwrap()
  assert_eq(browser.public_suffix(), "github.io")
  assert_eq(browser.registrable_domain(), Some("user.github.io"))
  assert_eq(browser.rule_section(), Some(PrivateSection))
  let icann = suffixes
    .lookup_with_options(
      "user.github.io",
      LookupOptions::new(IcannOnly, UseDefaultWildcard),
    )
    .unwrap()
  assert_eq(icann.public_suffix(), "io")
  assert_eq(icann.registrable_domain(), Some("github.io"))
  assert_eq(icann.rule_section(), Some(IcannSection))
}

///|
test "strict policy rejects unknown suffixes while defaults remain compatible" {
  let suffixes = sectioned_fixture()
  assert_eq(suffixes.lookup("service.internal").unwrap().matched_rule(), "*")
  assert_eq(suffixes.lookup("service.internal").unwrap().rule_section(), None)
  assert_true(
    suffixes.lookup_with_options(
      "service.internal",
      LookupOptions::strict_icann(),
    )
    is Err(UnlistedSuffix("service.internal")),
  )
}

///|
test "unsectioned custom rules stay eligible in ICANN-only mode" {
  let suffixes = SuffixList::parse("internal").unwrap()
  let result = suffixes
    .lookup_with_options("api.service.internal", LookupOptions::strict_icann())
    .unwrap()
  assert_eq(result.public_suffix(), "internal")
  assert_eq(result.rule_section(), Some(UnsectionedRule))
}

///|
test "serialize PSL text in a stable canonical order" {
  let suffixes = SuffixList::parse(
    (
      #|z.local trailing-field
      #|*.local
      #|z.local
      #|// ===BEGIN ICANN DOMAINS===
      #|org
      #|com
      #|*.kobe.jp
      #|!city.kobe.jp
      #|// ===END ICANN DOMAINS===
      #|// ===BEGIN PRIVATE DOMAINS===
      #|github.io
      #|blogspot.com
      #|// ===END PRIVATE DOMAINS===
      #|
    ),
  ).unwrap()
  assert_eq(
    suffixes.to_psl_text(),
    (
      #|*.local
      #|z.local
      #|
      #|// ===BEGIN ICANN DOMAINS===
      #|!city.kobe.jp
      #|*.kobe.jp
      #|com
      #|org
      #|// ===END ICANN DOMAINS===
      #|
      #|// ===BEGIN PRIVATE DOMAINS===
      #|blogspot.com
      #|github.io
      #|// ===END PRIVATE DOMAINS===
      #|
    ),
  )
  let reordered = SuffixList::parse(
    (
      #|*.local
      #|z.local
      #|// ===BEGIN ICANN DOMAINS===
      #|!city.kobe.jp
      #|*.kobe.jp
      #|com
      #|org
      #|// ===END ICANN DOMAINS===
      #|// ===BEGIN PRIVATE DOMAINS===
      #|blogspot.com
      #|github.io
      #|// ===END PRIVATE DOMAINS===
      #|
    ),
  ).unwrap()
  assert_eq(reordered.to_psl_text(), suffixes.to_psl_text())
}

///|
test "serialized rule sets round trip without semantic or byte drift" {
  let original = SuffixList::parse(
    (
      #|custom
      #|// ===BEGIN ICANN DOMAINS===
      #|com
      #|*.ck
      #|!www.ck
      #|// ===END ICANN DOMAINS===
      #|// ===BEGIN PRIVATE DOMAINS===
      #|com
      #|github.io
      #|// ===END PRIVATE DOMAINS===
      #|
    ),
  ).unwrap()
  let canonical = original.to_psl_text()
  let restored = SuffixList::parse(canonical).unwrap()
  assert_eq(restored.rule_count(), original.rule_count())
  assert_eq(restored.to_psl_text(), canonical)
  for domain in ["api.custom", "www.www.ck", "user.github.io", "unknown"] {
    let before = original.lookup(domain).unwrap()
    let after = restored.lookup(domain).unwrap()
    assert_eq(after.public_suffix(), before.public_suffix())
    assert_eq(after.registrable_domain(), before.registrable_domain())
    assert_eq(after.matched_rule(), before.matched_rule())
    assert_eq(after.rule_section(), before.rule_section())
  }
}

///|
test "empty rule sets serialize and round trip as empty text" {
  let empty = SuffixList::parse("").unwrap()
  assert_eq(empty.to_psl_text(), "")
  assert_eq(SuffixList::parse(empty.to_psl_text()).unwrap().rule_count(), 0)
}

///|
test "implicit wildcard handles unlisted suffixes" {
  let suffixes = official_semantics_fixture()
  let one = suffixes.lookup("example").unwrap()
  assert_eq(one.public_suffix(), "example")
  assert_eq(one.registrable_domain(), None)
  assert_eq(one.rule_kind(), DefaultRule)
  let two = suffixes.lookup("b.example.example").unwrap()
  assert_eq(two.public_suffix(), "example")
  assert_eq(two.registrable_domain(), Some("example.example"))
  assert_eq(two.matched_rule(), "*")
}

///|
test "exact rules choose the greatest label count" {
  let suffixes = official_semantics_fixture()
  assert_eq(suffixes.registrable_domain("biz").unwrap(), None)
  assert_eq(
    suffixes.registrable_domain("a.b.domain.biz").unwrap(),
    Some("domain.biz"),
  )
  let uk = suffixes.lookup("a.example.uk.com").unwrap()
  assert_eq(uk.public_suffix(), "uk.com")
  assert_eq(uk.registrable_domain(), Some("example.uk.com"))
  assert_eq(uk.rule_kind(), ExactRule)
}

///|
test "wildcard consumes one label and does not imply its base" {
  let suffixes = official_semantics_fixture()
  let base = suffixes.lookup("mm").unwrap()
  assert_eq(base.rule_kind(), DefaultRule)
  assert_eq(suffixes.registrable_domain("c.mm").unwrap(), None)
  let nested = suffixes.lookup("a.b.c.mm").unwrap()
  assert_eq(nested.public_suffix(), "c.mm")
  assert_eq(nested.registrable_domain(), Some("b.c.mm"))
  assert_eq(nested.matched_rule(), "*.mm")
}

///|
test "exception rules override wildcard matches" {
  let suffixes = official_semantics_fixture()
  assert_eq(suffixes.registrable_domain("test.ck").unwrap(), None)
  assert_eq(
    suffixes.registrable_domain("a.b.test.ck").unwrap(),
    Some("b.test.ck"),
  )
  let exception = suffixes.lookup("www.www.ck").unwrap()
  assert_eq(exception.public_suffix(), "ck")
  assert_eq(exception.registrable_domain(), Some("www.ck"))
  assert_eq(exception.matched_rule(), "!www.ck")
  assert_eq(exception.rule_kind(), ExceptionRule)
}

///|
test "complex exception shortens the prevailing rule" {
  let suffixes = official_semantics_fixture()
  assert_eq(suffixes.registrable_domain("c.kobe.jp").unwrap(), None)
  let city = suffixes.lookup("www.city.kobe.jp").unwrap()
  assert_eq(city.public_suffix(), "kobe.jp")
  assert_eq(city.registrable_domain(), Some("city.kobe.jp"))
}

///|
test "case normalization and one trailing root dot are preserved" {
  let suffixes = official_semantics_fixture()
  let result = suffixes.lookup("WwW.Example.COM.").unwrap()
  assert_eq(result.normalized_domain(), "www.example.com.")
  assert_eq(result.public_suffix(), "com.")
  assert_eq(result.registrable_domain(), Some("example.com."))
  assert_eq(result.matched_rule(), "com")
}

///|
test "unicode labels work when list and lookup use the same representation" {
  let suffixes = official_semantics_fixture()
  let result = suffixes.lookup("商店.公司.CN").unwrap()
  assert_eq(result.public_suffix(), "公司.cn")
  assert_eq(result.registrable_domain(), Some("商店.公司.cn"))
}

///|
test "reject empty labels and PSL metacharacters in domains" {
  let suffixes = official_semantics_fixture()
  assert_true(suffixes.lookup("") is Err(EmptyDomain))
  assert_true(suffixes.lookup(".example.com") is Err(EmptyLabel(0)))
  assert_true(suffixes.lookup("a..com") is Err(EmptyLabel(1)))
  assert_true(suffixes.lookup("example.com..") is Err(EmptyLabel(2)))
  assert_true(suffixes.lookup("*.example.com") is Err(_))
}

///|
test "focused convenience queries agree with lookup" {
  let suffixes = official_semantics_fixture()
  let result = suffixes.lookup("api.example.com").unwrap()
  assert_eq(
    suffixes.public_suffix("api.example.com").unwrap(),
    result.public_suffix(),
  )
  assert_eq(
    suffixes.registrable_domain("api.example.com").unwrap(),
    result.registrable_domain(),
  )
  assert_eq(suffixes.is_public_suffix("com").unwrap(), true)
  assert_eq(suffixes.is_public_suffix("example.com").unwrap(), false)
}
