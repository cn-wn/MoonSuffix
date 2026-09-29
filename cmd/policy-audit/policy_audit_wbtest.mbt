///|
test "parse policy audit options" {
  let config = parse_policy_audit_config([
    "rules.snapshot", "hosts.txt", "--idna", "--fail-on-impact",
  ])
  assert_eq(config.bundle_path, "rules.snapshot")
  assert_eq(config.hosts_path, "hosts.txt")
  assert_true(config.idna)
  assert_true(config.fail_on_impact)
  let defaults = parse_policy_audit_config(["rules.snapshot", "hosts.txt"])
  assert_true(!defaults.idna)
  assert_true(!defaults.fail_on_impact)
}

///|
test "policy audit retains order duplicates and reproducible snapshot identity" {
  let rules = "// ===BEGIN ICANN DOMAINS===\ncom\nio\n// ===END ICANN DOMAINS===\n" +
    "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n"
  let snapshot = @moonsuffix.SuffixList::parse(rules)
    .unwrap()
    .snapshot("release 1")
  let inventory = "# deployment sample\nuser.github.io\napi.net\napi.example.com\nuser.github.io\n"
  let first = run_policy_audit(snapshot.bundle_text(), inventory, false).unwrap()
  let second = run_policy_audit(snapshot.bundle_text(), inventory, false).unwrap()
  assert_eq(first.report, second.report)
  assert_eq(first.scanned_count, 4)
  assert_eq(first.changed_count, 3)
  assert_true(first.report.contains("source_revision=release%201\n"))
  assert_true(first.report.contains("psl_sha256=\{snapshot.sha256()}\n"))
  assert_true(
    first.report.contains("before_policy=browser\nafter_policy=strict-icann\n"),
  )
  assert_true(
    first.report.contains(
      "hosts_scanned=4\nhosts_changed=3\nhosts_unchanged=1\n",
    ),
  )
  assert_true(first.report.contains("\"0\",\"user.github.io\""))
  assert_true(first.report.contains("\"1\",\"api.net\""))
  assert_true(first.report.contains("\"3\",\"user.github.io\""))
  assert_true(!first.report.contains("\"2\",\"api.example.com\""))
  assert_true(policy_audit_gate_error(first) is Some(_))
}

///|
test "policy audit validates snapshot and inventory before comparison" {
  let bundle = @moonsuffix.SuffixList::parse("com\n")
    .unwrap()
    .snapshot("v1")
    .bundle_text()
  assert_true(
    run_policy_audit("not a bundle", "api.com", false) is Err(message) &&
    message.has_prefix("invalid snapshot:"),
  )
  assert_true(
    run_policy_audit(bundle.replace(old="com\n", new="net\n"), "api.com", false)
    is Err(message) &&
    message.has_prefix("invalid snapshot:"),
  )
  assert_true(
    run_policy_audit(bundle, "api.com\nbad..com\n", false) is Err(message) &&
    message.has_prefix("hostname inventory line 2:"),
  )
  let unaffected = run_policy_audit(bundle, "api.com\n", false).unwrap()
  assert_eq(unaffected.changed_count, 0)
  assert_eq(policy_audit_gate_error(unaffected), None)
  let empty = run_policy_audit(bundle, "# no hosts\n", false).unwrap()
  assert_eq(empty.scanned_count, 0)
  assert_true(
    policy_audit_gate_error(empty) is Some(message) && message.contains("empty"),
  )
}

///|
test "policy audit normalizes Unicode hosts when requested" {
  let rules = "// ===BEGIN ICANN DOMAINS===\ncn\n// ===END ICANN DOMAINS===\n" +
    "// ===BEGIN PRIVATE DOMAINS===\n公司.cn\n// ===END PRIVATE DOMAINS===\n"
  let bundle = @suffix_idna.parse_psl(rules)
    .unwrap()
    .snapshot("unicode")
    .bundle_text()
  let report = run_policy_audit(bundle, "商店.公司.cn\n", true).unwrap()
  assert_eq(report.changed_count, 1)
  assert_true(report.report.contains("xn--55qx5d.cn"))
  assert_true(
    run_policy_audit(bundle, "商店..公司.cn\n", true) is Err(message) &&
    message.has_prefix("hostname inventory line 1:"),
  )
}
