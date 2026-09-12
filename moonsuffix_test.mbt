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
