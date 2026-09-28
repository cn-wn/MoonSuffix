///|
test "parse audit command arguments" {
  let config = parse_audit_config([
    "old.psl", "new.psl", "hosts.txt", "--from", "release-1", "--to", "release-2",
    "--strict-icann", "--fail-on-impact",
  ])
  assert_eq(config.old_psl_path, "old.psl")
  assert_eq(config.new_psl_path, "new.psl")
  assert_eq(config.hosts_path, "hosts.txt")
  assert_eq(config.cookie_inventory_path, None)
  assert_eq(config.from_revision, Some("release-1"))
  assert_eq(config.to_revision, Some("release-2"))
  assert_true(config.strict_icann)
  assert_true(config.fail_on_impact)
  assert_true(!config.bundles)
}

///|
test "bundle audit mode reads revision labels from snapshots" {
  let config = parse_audit_config([
    "old.snapshot", "new.snapshot", "hosts.txt", "--bundles", "--strict-icann",
  ])
  assert_true(config.bundles)
  assert_eq(config.from_revision, None)
  assert_eq(config.to_revision, None)
  assert_eq(config.cookie_inventory_path, None)
}

///|
test "parse hostname inventories deterministically" {
  let hosts = parse_host_inventory(
    "\n # inventory\r\napi.example.com\r\n api.net \napi.example.com\n",
  )
  assert_eq(hosts, ["api.example.com", "api.net", "api.example.com"])
}

///|
test "parse optional Cookie inventory without losing absent or empty attributes" {
  let config = parse_audit_config([
    "old.psl", "new.psl", "hosts.txt", "--from", "old", "--to", "new", "--cookie-inventory",
    "cookies.tsv",
  ])
  assert_eq(config.cookie_inventory_path, Some("cookies.tsv"))
  let inputs = parse_cookie_inventory(
    "# cookie cases\r\napi.example.com\r\nshop.example.com\texample.com\n" +
    "shop.example.com\t\nshop.example.com\texample.com\n",
  ).unwrap()
  assert_eq(inputs.length(), 4)
  assert_eq(inputs[0].request_host(), "api.example.com")
  assert_eq(inputs[0].domain_attribute(), None)
  assert_eq(inputs[1].domain_attribute(), Some("example.com"))
  assert_eq(inputs[2].domain_attribute(), Some(""))
  assert_eq(inputs[3].domain_attribute(), Some("example.com"))
  assert_true(
    parse_cookie_inventory("a.com\tb.com\textra")
    is Err(
      "cookie inventory line 1: expected a host and at most one Domain field"
    ),
  )
  assert_eq(parse_cookie_inventory("# empty\n").unwrap().length(), 0)
}

///|
test "render a deterministic update audit" {
  let old_psl =
    #|// ===BEGIN ICANN DOMAINS===
    #|com
    #|io
    #|// ===END ICANN DOMAINS===
    #|// ===BEGIN PRIVATE DOMAINS===
    #|github.io
    #|// ===END PRIVATE DOMAINS===
  let new_psl =
    #|// ===BEGIN ICANN DOMAINS===
    #|com
    #|github.io
    #|io
    #|net
    #|// ===END ICANN DOMAINS===
  let hosts = "user.github.io\napi.net\napi.example.com\n"
  let first = build_audit_report(
    old_psl,
    new_psl,
    hosts,
    None,
    "release-1",
    "release-2",
    true,
  ).unwrap()
  let second = build_audit_report(
    old_psl,
    new_psl,
    hosts,
    None,
    "release-1",
    "release-2",
    true,
  ).unwrap()
  assert_eq(first.report, second.report)
  assert_eq(first.changed_count, 2)
  let first = first.report
  assert_true(first.contains("format=moonsuffix-audit-v1\n"))
  assert_true(first.contains("policy=strict-icann\n"))
  assert_true(first.contains("old_rules=3\nnew_rules=4\n"))
  assert_true(
    first.contains("hosts_scanned=3\nhosts_changed=2\nhosts_unchanged=1\n"),
  )
  assert_true(first.contains("added=1\nremoved=0\nmoved=1\n"))
  assert_true(first.contains("> [PRIVATE->ICANN] github.io\n"))
  assert_true(first.contains("\"0\",\"user.github.io\",\"boundary_changed\""))
  assert_true(first.contains("\"1\",\"api.net\",\"became_accepted\""))
  assert_true(!first.contains("\"2\",\"api.example.com\""))
  assert_true(!first.contains("cookie_scope_impact_csv:"))
}

///|
test "Cookie-only changes extend the audit report and gate count" {
  let old_psl = "// ===BEGIN ICANN DOMAINS===\ncom\nio\n// ===END ICANN DOMAINS===\n" +
    "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n"
  let new_psl = "// ===BEGIN ICANN DOMAINS===\ncom\ngithub.io\nio\nnet\n// ===END ICANN DOMAINS===\n"
  let cookies = "alice.github.io\tgithub.io\n" +
    "github.io\tgithub.io\n" +
    "api.net\n" +
    "api.example.com\texample.com\n"
  let raw = build_audit_report(
    old_psl,
    new_psl,
    "api.example.com\n",
    Some(cookies),
    "old",
    "new",
    true,
  ).unwrap()
  assert_eq(raw.changed_count, 3)
  assert_true(raw.report.contains("hosts_changed=0\n"))
  assert_true(raw.report.contains("cookies_scanned=4\n"))
  assert_true(raw.report.contains("cookies_changed=3\n"))
  assert_true(raw.report.contains("cookies_unchanged=1\n"))
  assert_true(raw.report.contains("cookie_scope_impact_csv:\n"))
  assert_true(
    raw.report.contains(
      "\"0\",\"alice.github.io\",\"true\",\"github.io\",\"became_rejected\"",
    ),
  )
  assert_true(
    raw.report.contains(
      "\"1\",\"github.io\",\"true\",\"github.io\",\"scope_changed\"",
    ),
  )
  assert_true(
    raw.report.contains("\"2\",\"api.net\",\"false\",\"\",\"became_accepted\""),
  )
  let old_bundle = @moonsuffix.SuffixList::parse(old_psl)
    .unwrap()
    .snapshot("old")
    .bundle_text()
  let new_bundle = @moonsuffix.SuffixList::parse(new_psl)
    .unwrap()
    .snapshot("new")
    .bundle_text()
  let bundled = build_bundle_audit_report(
    old_bundle,
    new_bundle,
    "api.example.com\n",
    Some(cookies),
    true,
  ).unwrap()
  assert_eq(bundled.report, raw.report)
  assert_eq(bundled.changed_count, 3)
  assert_true(
    build_audit_report(
      old_psl,
      new_psl,
      "api.example.com\n",
      Some("a.com\tb.com\textra"),
      "old",
      "new",
      true,
    )
    is Err(message) &&
    message.has_prefix("cookie inventory line 1:"),
  )
}

///|
test "audit gate counts only actual hostname effects" {
  let old_psl = "com\n"
  let new_psl = "com\nnet\n"
  let changed = build_audit_report(
    old_psl,
    new_psl,
    "api.net\n",
    None,
    "old",
    "new",
    true,
  ).unwrap()
  assert_eq(changed.changed_count, 1)
  let unaffected = build_audit_report(
    old_psl,
    new_psl,
    "api.com\n",
    None,
    "old",
    "new",
    true,
  ).unwrap()
  assert_eq(unaffected.changed_count, 0)
  assert_true(unaffected.report.contains("added=1\n"))
  let empty = build_audit_report(
    old_psl,
    new_psl,
    "# no hosts\n",
    None,
    "old",
    "new",
    true,
  ).unwrap()
  assert_eq(empty.changed_count, 0)
}

///|
test "stored bundle audit matches raw PSL audit" {
  let old_psl = "com\n"
  let new_psl = "com\nnet\n"
  let old = @moonsuffix.SuffixList::parse(old_psl)
    .unwrap()
    .snapshot("release 1")
    .bundle_text()
  let new = @moonsuffix.SuffixList::parse(new_psl)
    .unwrap()
    .snapshot("release 2")
    .bundle_text()
  let bundled = build_bundle_audit_report(old, new, "api.net\n", None, true).unwrap()
  let raw = build_audit_report(
    old_psl,
    new_psl,
    "api.net\n",
    None,
    "release 1",
    "release 2",
    true,
  ).unwrap()
  assert_eq(bundled.report, raw.report)
  assert_eq(bundled.changed_count, 1)
}

///|
test "stored bundle audit rejects tampering before impact analysis" {
  let valid = @moonsuffix.SuffixList::parse("com\n")
    .unwrap()
    .snapshot("v1")
    .bundle_text()
  assert_true(
    build_bundle_audit_report("broken", valid, "api.com", None, false)
    is Err(message) &&
    message.has_prefix("old snapshot:"),
  )
  assert_true(
    build_bundle_audit_report(valid, "broken", "api.com", None, false)
    is Err(message) &&
    message.has_prefix("candidate snapshot:"),
  )
  assert_eq(
    build_bundle_audit_report(valid, valid, "api.com", None, false).unwrap().changed_count,
    0,
  )
}

///|
test "identify which PSL input is malformed" {
  let old_error = build_audit_report(
    "foo.*.com",
    "com",
    "api.example.com",
    None,
    "old",
    "new",
    false,
  )
  assert_true(old_error is Err(message) && message.has_prefix("old PSL:"))
  let new_error = build_audit_report(
    "com",
    "foo.*.com",
    "api.example.com",
    None,
    "old",
    "new",
    false,
  )
  assert_true(new_error is Err(message) && message.has_prefix("candidate PSL:"))
}
