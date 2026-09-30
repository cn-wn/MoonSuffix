///|
test "parse raw and bundle conformance command arguments" {
  let raw = parse_conformance_config(["rules.psl", "cases.txt"])
  assert_eq(raw.rules_path, "rules.psl")
  assert_eq(raw.tests_path, "cases.txt")
  assert_eq(raw.bundle, false)
  assert_eq(raw.idna, false)
  let bundle = parse_conformance_config([
    "rules.snapshot", "cases.txt", "--bundle",
  ])
  assert_eq(bundle.rules_path, "rules.snapshot")
  assert_eq(bundle.bundle, true)
  let idna = parse_conformance_config(["rules.psl", "cases.txt", "--idna"])
  assert_eq(idna.idna, true)
}

///|
test "conformance command reports reproducible success and failure counts" {
  let rules = "com\n*.ck\n!www.ck\n"
  let cases = "checkPublicSuffix('example.com', 'example.com');\n" +
    "checkPublicSuffix('www.www.ck', 'www.ck');\n"
  let success = run_conformance(rules, cases, false, false).unwrap()
  assert_eq(success.failure_count, 0)
  assert_true(success.text.contains("source_revision=raw-input\n"))
  assert_true(success.text.contains("rule_count=3\n"))
  assert_true(success.text.contains("cases=2\npassed=2\nfailed=0\n"))
  assert_true(
    success.text.has_suffix("\"line\",\"input\",\"expected\",\"actual\"\n"),
  )
  assert_eq(
    run_conformance(rules, cases, false, false).unwrap().text,
    success.text,
  )
  let failure = run_conformance(
    rules, "checkPublicSuffix('example.com', 'wrong.com');\n", false, false,
  ).unwrap()
  assert_eq(failure.failure_count, 1)
  assert_true(failure.text.contains("cases=1\npassed=0\nfailed=1\n"))
  assert_true(
    failure.text.contains("\"1\",\"example.com\",\"wrong.com\",\"example.com\""),
  )
}

///|
test "conformance command rejects empty and malformed test files" {
  assert_true(
    run_conformance("com", "// no cases\n", false, false)
    is Err("conformance test file contains no cases"),
  )
  assert_true(
    run_conformance("com", "checkPublicSuffix('com');", false, false)
    is Err(message) &&
    message.contains("line 1"),
  )
  assert_true(
    run_conformance(
      "foo.*.com", "checkPublicSuffix('com', null);", false, false,
    )
    is Err(message) &&
    message.contains("invalid PSL rule"),
  )
  assert_eq(
    run_conformance(
      "com", "checkPublicSuffix('example.com', 'example.com');", false, false,
    ).unwrap().failure_count,
    0,
  )
}

///|
test "verified bundle preserves provenance and rejects tampering" {
  let rules = "com\n公司.cn\n"
  let snapshot = @moonsuffix.SuffixList::parse(rules)
    .unwrap()
    .snapshot("release 2026/秋")
  let cases = "checkPublicSuffix('商店.公司.cn', '商店.公司.cn');\n"
  let bundled = run_conformance(snapshot.bundle_text(), cases, true, false).unwrap()
  let raw = run_conformance(rules, cases, false, false).unwrap()
  assert_eq(bundled.failure_count, 0)
  assert_true(
    bundled.text.contains("source_revision=release%202026%2f%e7%a7%8b\n"),
  )
  assert_true(bundled.text.contains("psl_sha256=\{snapshot.sha256()}\n"))
  assert_true(raw.text.contains("psl_sha256=\{snapshot.sha256()}\n"))
  assert_true(
    run_conformance(
      snapshot.bundle_text().replace(old="com\n", new="net\n"),
      cases,
      true,
      false,
    )
    is Err(message) &&
    message.has_prefix("invalid snapshot:"),
  )
}

///|
test "IDNA conformance normalizes Unicode rules inputs and expectations" {
  let rules = "// ===BEGIN ICANN DOMAINS===\n公司.cn\n// ===END ICANN DOMAINS===\n"
  let cases = "checkPublicSuffix('商店.公司.cn', '商店.公司.cn');\n" +
    "checkPublicSuffix('xn--czrs0t.xn--55qx5d.cn', 'xn--czrs0t.xn--55qx5d.cn');\n" +
    "checkPublicSuffix('公司.cn', null);\n"
  let result = run_conformance(rules, cases, false, true).unwrap()
  assert_eq(result.failure_count, 0)
  assert_true(result.text.contains("cases=3\npassed=3\nfailed=0\n"))
  let snapshot = @suffix_idna.parse_psl(rules).unwrap().snapshot("pinned")
  assert_eq(
    run_conformance(snapshot.bundle_text(), cases, true, true).unwrap().failure_count,
    0,
  )
}
