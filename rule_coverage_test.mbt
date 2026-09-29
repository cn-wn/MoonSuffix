///|
fn coverage_fixture() -> @moonsuffix.SuffixList {
  @moonsuffix.SuffixList::parse(
    "local\n" +
    "// ===BEGIN ICANN DOMAINS===\ncom\nck\n*.ck\n!www.ck\nio\n// ===END ICANN DOMAINS===\n" +
    "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\ncom\n// ===END PRIVATE DOMAINS===\n",
  ).unwrap()
}

///|
test "rule coverage counts exact wildcard exception and private selections" {
  let list = coverage_fixture()
  let domains = [
    "shop.example.com", "a.test.ck", "www.www.ck", "a.github.io", "service.internal",
    "a..com", "shop.example.com", "com",
  ]
  let report = list.analyze_rule_coverage(
    domains,
    @moonsuffix.LookupOptions::browser_default(),
  )
  assert_eq(report.scanned_count(), 8)
  assert_eq(report.explicit_count(), 6)
  assert_eq(report.implicit_count(), 1)
  assert_eq(report.unlisted_count(), 0)
  assert_eq(report.invalid_count(), 1)
  assert_eq(report.observed_rule_count(), 4)
  assert_eq(report.unobserved_rule_count(), 4)
  assert_eq(report.entries().length(), list.rule_count())
  assert_eq(report.entries()[1].kind(), ExceptionRule)
  assert_eq(report.entries()[2].kind(), WildcardRule)
  assert_eq(report.entries()[4].section(), IcannSection)
  assert_eq(report.entries()[4].selected_count(), 3)
  assert_eq(report.entries()[6].section(), PrivateSection)
  assert_eq(report.entries()[6].selected_count(), 0)
  assert_eq(report.entries()[7].selected_count(), 1)
  assert_eq(
    report.to_csv(),
    "\"section\",\"rule\",\"kind\",\"selected_count\"\n" +
    "\"unsectioned\",\"local\",\"exact\",\"0\"\n" +
    "\"ICANN\",\"!www.ck\",\"exception\",\"1\"\n" +
    "\"ICANN\",\"*.ck\",\"wildcard\",\"1\"\n" +
    "\"ICANN\",\"ck\",\"exact\",\"0\"\n" +
    "\"ICANN\",\"com\",\"exact\",\"3\"\n" +
    "\"ICANN\",\"io\",\"exact\",\"0\"\n" +
    "\"PRIVATE\",\"com\",\"exact\",\"0\"\n" +
    "\"PRIVATE\",\"github.io\",\"exact\",\"1\"\n",
  )
}

///|
test "strict policy separates unlisted names from invalid names" {
  let report = coverage_fixture().analyze_rule_coverage(
    ["a.github.io", "service.internal", "a..com", "api.example.com"],
    @moonsuffix.LookupOptions::strict_icann(),
  )
  assert_eq(report.scanned_count(), 4)
  assert_eq(report.explicit_count(), 2)
  assert_eq(report.implicit_count(), 0)
  assert_eq(report.unlisted_count(), 1)
  assert_eq(report.invalid_count(), 1)
  assert_eq(report.entries()[5].rule(), "io")
  assert_eq(report.entries()[5].selected_count(), 1)
  assert_eq(report.entries()[7].selected_count(), 0)
}

///|
test "coverage includes every rule for an empty inventory and ignores rule order" {
  let empty = coverage_fixture().analyze_rule_coverage(
    [],
    @moonsuffix.LookupOptions::browser_default(),
  )
  assert_eq(empty.scanned_count(), 0)
  assert_eq(empty.explicit_count(), 0)
  assert_eq(empty.implicit_count(), 0)
  assert_eq(empty.unlisted_count(), 0)
  assert_eq(empty.invalid_count(), 0)
  assert_eq(empty.observed_rule_count(), 0)
  assert_eq(empty.unobserved_rule_count(), 8)
  let reordered = @moonsuffix.SuffixList::parse(
    "local\n" +
    "// ===BEGIN ICANN DOMAINS===\nio\n!www.ck\n*.ck\nck\ncom\n// ===END ICANN DOMAINS===\n" +
    "// ===BEGIN PRIVATE DOMAINS===\ncom\ngithub.io\n// ===END PRIVATE DOMAINS===\n",
  ).unwrap()
  assert_eq(
    empty.to_csv(),
    reordered
    .analyze_rule_coverage([], @moonsuffix.LookupOptions::browser_default())
    .to_csv(),
  )
}
