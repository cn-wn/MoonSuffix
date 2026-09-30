///|
test "benchmark rejects unusable input and records nonzero work" {
  assert_eq(
    run_benchmark("com\n", "# no hosts\n", false, 1, 1),
    Err("benchmark inventory is empty"),
  )
  assert_true(
    run_benchmark("com\n", "a..com\n", false, 1, 1) is Err(message) &&
    message.contains("inventory line 1"),
  )
  let report = run_benchmark("com\n", "a.com\n b.com\n", false, 1, 2).unwrap()
  assert_true(report.contains("rule_count=1\nhost_count=2\nidna=false\n"))
  assert_true(report.contains("parse_checksum=1\n"))
  assert_true(report.contains("lookup_checksum=12\n"))
  assert_true(report.contains("lookup_mean_us_per_host="))
}

///|
test "benchmark normalizes Unicode inputs before measuring lookup" {
  let report = run_benchmark("公司.cn\n", "商店.公司.cn\n", true, 1, 2).unwrap()
  assert_true(report.contains("host_count=1\nidna=true\n"))
  assert_true(report.contains("lookup_checksum=26\n"))
}
