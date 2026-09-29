///|
test "IDNA batch preserves Unicode inputs, order, and row-level errors" {
  let list = parse_psl(
    "// ===BEGIN ICANN DOMAINS===\n公司.cn\ncom\n// ===END ICANN DOMAINS===\n",
  ).unwrap()
  let report = lookup_batch_with_options(
    list,
    [
      "商店.公司.cn", "商店..公司.cn", "api.unknown", "xn--czrs0t.xn--55qx5d.cn",
      "商店.公司.cn",
    ],
    @moonsuffix.LookupOptions::strict_icann(),
  )
  assert_eq(report.length(), 5)
  assert_eq(report.success_count(), 3)
  assert_eq(report.error_count(), 2)
  assert_eq(report.items()[0].index(), 0)
  assert_eq(report.items()[4].input(), "商店.公司.cn")
  assert_true(report.items()[1].result() is Err(InvalidHostname(_, _)))
  assert_true(
    report.items()[2].result()
    is Err(InvalidDomain(@moonsuffix.UnlistedSuffix(_))),
  )
  assert_eq(
    report.items()[0].result().unwrap().normalized_domain(),
    report.items()[3].result().unwrap().normalized_domain(),
  )
  let csv = report.to_csv()
  assert_true(
    csv.contains(
      "\"0\",\"商店.公司.cn\",\"ok\",\"xn--czrs0t.xn--55qx5d.cn\"",
    ),
  )
  assert_true(csv.contains("\"1\",\"商店..公司.cn\",\"error\""))
  assert_true(csv.contains("\"2\",\"api.unknown\",\"error\""))
  assert_true(csv.contains("\"4\",\"商店.公司.cn\",\"ok\""))
  assert_eq(
    lookup_batch_with_options(
      list,
      [
        "商店.公司.cn", "商店..公司.cn", "api.unknown", "xn--czrs0t.xn--55qx5d.cn",
        "商店.公司.cn",
      ],
      @moonsuffix.LookupOptions::strict_icann(),
    ).to_csv(),
    csv,
  )
}

///|
test "IDNA batch handles empty input and escapes original text in CSV" {
  let list = parse_psl("com\n").unwrap()
  let empty = lookup_batch(list, [])
  assert_eq(empty.length(), 0)
  assert_eq(empty.success_count(), 0)
  assert_eq(empty.error_count(), 0)
  assert_true(empty.to_csv().has_suffix("\"error\"\n"))
  let report = lookup_batch(list, ["a\".com", "shop.com"])
  assert_eq(report.length(), 2)
  assert_true(report.to_csv().contains("\"a\"\".com\""))
  assert_true(report.items()[1].result() is Ok(_))
  assert_eq(
    lookup_batch(list, ["shop.com"]).to_csv(),
    list.lookup_batch(["shop.com"]).to_csv(),
  )
}
