///|
test "one compiled comparison can audit host and Cookie inventories repeatedly" {
  let old = @moonsuffix.SuffixList::parse(
      "// ===BEGIN ICANN DOMAINS===\napp\ncom\n// ===END ICANN DOMAINS===\n",
    )
    .unwrap()
    .snapshot("old")
  let candidate = @moonsuffix.SuffixList::parse(
      "// ===BEGIN ICANN DOMAINS===\napp\ncom\n// ===END ICANN DOMAINS===\n" +
      "// ===BEGIN PRIVATE DOMAINS===\nglideos.app\n// ===END PRIVATE DOMAINS===\n",
    )
    .unwrap()
    .snapshot("candidate")
  let comparison = old.compare_to(candidate)
  let browser = @moonsuffix.LookupOptions::browser_default()
  let hosts = ["api.glideos.app", "shop.example.com", "api.glideos.app"]
  let cookies = [
    @moonsuffix.CookieScopeInput::new("api.glideos.app", Some(".glideos.app")),
    @moonsuffix.CookieScopeInput::new("shop.example.com", None),
  ]
  let host_report = comparison.analyze_impact(hosts, browser)
  assert_eq(host_report.scanned_count(), 3)
  assert_eq(host_report.changed_count(), 2)
  assert_eq(host_report.impacts()[0].index(), 0)
  assert_eq(host_report.impacts()[1].index(), 2)
  assert_eq(
    host_report.to_csv(),
    old.analyze_impact(candidate, hosts, browser).to_csv(),
  )
  assert_eq(
    host_report.to_csv(),
    comparison.analyze_impact(hosts, browser).to_csv(),
  )
  let cookie_report = comparison.analyze_cookie_scope_impact(cookies, browser)
  assert_eq(cookie_report.scanned_count(), 2)
  assert_eq(cookie_report.changed_count(), 1)
  assert_true(cookie_report.impacts()[0].kind() is CookieBecameRejected)
  assert_eq(
    cookie_report.to_csv(),
    old.analyze_cookie_scope_impact(candidate, cookies, browser).to_csv(),
  )
  let strict = @moonsuffix.LookupOptions::strict_icann()
  assert_eq(comparison.analyze_impact(hosts, strict).changed_count(), 0)
  assert_eq(
    comparison.analyze_cookie_scope_impact(cookies, strict).changed_count(),
    0,
  )
}
