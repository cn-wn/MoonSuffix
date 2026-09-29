///|
test "parse classify command options" {
  let config = parse_classify_config([
    "rules.snapshot", "hosts.txt", "--strict-icann", "--fail-on-error",
  ])
  assert_eq(config.bundle_path, "rules.snapshot")
  assert_eq(config.hosts_path, "hosts.txt")
  assert_true(config.strict_icann)
  assert_true(config.fail_on_error)
  assert_true(!config.idna)
  let defaults = parse_classify_config(["rules.snapshot", "hosts.txt"])
  assert_true(!defaults.strict_icann)
  assert_true(!defaults.fail_on_error)
  assert_true(!defaults.idna)
  let unicode = parse_classify_config(["rules.snapshot", "hosts.txt", "--idna"])
  assert_true(unicode.idna)
}

///|
test "classify inventory filters comments but retains order and duplicates" {
  assert_eq(
    parse_classify_hosts(
      "\n # comment\r\n api.example.com \napi.net\napi.example.com\n",
    ),
    ["api.example.com", "api.net", "api.example.com"],
  )
}

///|
test "classification keeps invalid rows and recovers on later hosts" {
  let rules = "// ===BEGIN ICANN DOMAINS===\ncom\nio\n// ===END ICANN DOMAINS===\n" +
    "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n"
  let snapshot = @moonsuffix.SuffixList::parse(rules)
    .unwrap()
    .snapshot("release 1")
  let hosts = "# input\napi.example.com\na..com\napi.net\napi.example.com\n"
  let strict = run_classification(snapshot.bundle_text(), hosts, true, false).unwrap()
  assert_eq(strict.scanned_count, 4)
  assert_eq(strict.error_count, 2)
  assert_true(strict.report.contains("source_revision=release%201\n"))
  assert_true(strict.report.contains("psl_sha256=\{snapshot.sha256()}\n"))
  assert_true(strict.report.contains("policy=strict-icann\n"))
  assert_true(
    strict.report.contains(
      "hosts_scanned=4\nhosts_succeeded=2\nhosts_failed=2\n",
    ),
  )
  assert_true(strict.report.contains("\"0\",\"api.example.com\",\"ok\""))
  assert_true(strict.report.contains("\"1\",\"a..com\",\"error\""))
  assert_true(strict.report.contains("\"2\",\"api.net\",\"error\""))
  assert_true(strict.report.contains("\"3\",\"api.example.com\",\"ok\""))
  assert_eq(
    run_classification(snapshot.bundle_text(), hosts, true, false).unwrap().report,
    strict.report,
  )
  assert_true(classification_gate_error(strict) is Some(_))
  let browser = run_classification(snapshot.bundle_text(), hosts, false, false).unwrap()
  assert_eq(browser.error_count, 1)
  assert_true(browser.report.contains("\"2\",\"api.net\",\"ok\""))
}

///|
test "classification validates bundles and gate coverage" {
  let bundle = @moonsuffix.SuffixList::parse("com\n")
    .unwrap()
    .snapshot("v1")
    .bundle_text()
  assert_true(
    run_classification("broken", "api.com", false, false) is Err(message) &&
    message.has_prefix("invalid snapshot:"),
  )
  assert_true(
    run_classification(
      bundle.replace(old="com\n", new="net\n"),
      "api.com",
      false,
      false,
    )
    is Err(message) &&
    message.has_prefix("invalid snapshot:"),
  )
  let empty = run_classification(bundle, "# no hosts\n", false, false).unwrap()
  assert_eq(empty.scanned_count, 0)
  assert_true(
    classification_gate_error(empty) is Some(message) &&
    message.contains("empty"),
  )
  let success = run_classification(bundle, "api.com\n", true, false).unwrap()
  assert_eq(success.error_count, 0)
  assert_eq(classification_gate_error(success), None)
}

///|
test "IDNA classification retains invalid Unicode rows and later results" {
  let rules = "// ===BEGIN ICANN DOMAINS===\n公司.cn\n// ===END ICANN DOMAINS===\n"
  let bundle = @suffix_idna.parse_psl(rules)
    .unwrap()
    .snapshot("unicode-v1")
    .bundle_text()
  let inventory = "商店.公司.cn\n商店..公司.cn\nxn--czrs0t.xn--55qx5d.cn\n"
  let result = run_classification(bundle, inventory, true, true).unwrap()
  assert_eq(result.scanned_count, 3)
  assert_eq(result.error_count, 1)
  assert_true(
    result.report.contains(
      "hosts_scanned=3\nhosts_succeeded=2\nhosts_failed=1\n",
    ),
  )
  assert_true(
    result.report.contains(
      "\"0\",\"商店.公司.cn\",\"ok\",\"xn--czrs0t.xn--55qx5d.cn\"",
    ),
  )
  assert_true(result.report.contains("\"1\",\"商店..公司.cn\",\"error\""))
  assert_true(
    result.report.contains("\"2\",\"xn--czrs0t.xn--55qx5d.cn\",\"ok\""),
  )
  assert_true(classification_gate_error(result) is Some(_))
}
