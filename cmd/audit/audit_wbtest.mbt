///|
test "parse audit command arguments" {
  let config = parse_audit_config([
    "old.psl", "new.psl", "hosts.txt", "--from", "release-1", "--to", "release-2",
    "--strict-icann", "--fail-on-impact",
  ])
  assert_eq(config.old_psl_path, "old.psl")
  assert_eq(config.new_psl_path, "new.psl")
  assert_eq(config.hosts_path, "hosts.txt")
  assert_eq(config.from_revision, "release-1")
  assert_eq(config.to_revision, "release-2")
  assert_true(config.strict_icann)
  assert_true(config.fail_on_impact)
}

///|
test "parse hostname inventories deterministically" {
  let hosts = parse_host_inventory(
    "\n # inventory\r\napi.example.com\r\n api.net \napi.example.com\n",
  )
  assert_eq(hosts, ["api.example.com", "api.net", "api.example.com"])
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
    old_psl, new_psl, hosts, "release-1", "release-2", true,
  ).unwrap()
  let second = build_audit_report(
    old_psl, new_psl, hosts, "release-1", "release-2", true,
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
}

///|
test "audit gate counts only actual hostname effects" {
  let old_psl = "com\n"
  let new_psl = "com\nnet\n"
  let changed = build_audit_report(
    old_psl, new_psl, "api.net\n", "old", "new", true,
  ).unwrap()
  assert_eq(changed.changed_count, 1)
  let unaffected = build_audit_report(
    old_psl, new_psl, "api.com\n", "old", "new", true,
  ).unwrap()
  assert_eq(unaffected.changed_count, 0)
  assert_true(unaffected.report.contains("added=1\n"))
  let empty = build_audit_report(
    old_psl, new_psl, "# no hosts\n", "old", "new", true,
  ).unwrap()
  assert_eq(empty.changed_count, 0)
}

///|
test "identify which PSL input is malformed" {
  let old_error = build_audit_report(
    "foo.*.com", "com", "api.example.com", "old", "new", false,
  )
  assert_true(old_error is Err(message) && message.has_prefix("old PSL:"))
  let new_error = build_audit_report(
    "com", "foo.*.com", "api.example.com", "old", "new", false,
  )
  assert_true(new_error is Err(message) && message.has_prefix("candidate PSL:"))
}
