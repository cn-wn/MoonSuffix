///|
test "lookup command parses policy and IDNA options" {
  let config = parse_lookup_config([
    "unicode.snapshot", "商店.公司.cn", "--idna", "--strict-icann",
  ])
  assert_eq(config.bundle_path, "unicode.snapshot")
  assert_eq(config.hostname, "商店.公司.cn")
  assert_true(config.idna)
  assert_true(config.strict_icann)
}

///|
test "query reports provenance and matched Unicode domain boundary" {
  let bundle = @suffix_idna.parse_psl(
      "// ===BEGIN ICANN DOMAINS===\n公司.cn\n// ===END ICANN DOMAINS===\n",
    )
    .unwrap()
    .snapshot("unicode-v1")
    .bundle_text()
  let report = query_bundle(bundle, "商店.公司.cn", true, true).unwrap()
  assert_true(report.contains("source_revision=unicode-v1\n"))
  assert_true(report.contains("normalized_domain=xn--czrs0t.xn--55qx5d.cn\n"))
  assert_true(report.contains("public_suffix=xn--55qx5d.cn\n"))
  assert_true(report.contains("registrable_domain=xn--czrs0t.xn--55qx5d.cn\n"))
  assert_true(report.contains("matched_rule=xn--55qx5d.cn\n"))
  assert_true(report.contains("rule_kind=exact\nrule_section=ICANN\n"))
  let ascii = query_bundle(bundle, "xn--czrs0t.xn--55qx5d.cn", false, true).unwrap()
  assert_eq(report, ascii)
}

///|
test "query rejects corrupt bundles and strict unknown suffixes" {
  assert_true(
    query_bundle("broken", "api.example.com", false, false) is Err(message) &&
    message.has_prefix("invalid snapshot:"),
  )
  let bundle = @moonsuffix.SuffixList::parse("com")
    .unwrap()
    .snapshot("v1")
    .bundle_text()
  assert_true(
    query_bundle(bundle, "api.internal", false, true) is Err(message) &&
    message.contains("no suffix listed"),
  )
  assert_true(query_bundle(bundle, "api.example.com", false, true) is Ok(_))
}
