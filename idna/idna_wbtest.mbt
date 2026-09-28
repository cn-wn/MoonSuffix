///|
test "Unicode and A-label names resolve to the same boundary" {
  let list = parse_psl(
    "// ===BEGIN ICANN DOMAINS===\n公司.cn\n// ===END ICANN DOMAINS===\n",
  ).unwrap()
  let unicode = lookup(list, "商店.公司.CN").unwrap()
  let ascii = lookup(list, "xn--czrs0t.xn--55qx5d.cn").unwrap()
  assert_eq(unicode.public_suffix(), "xn--55qx5d.cn")
  assert_eq(unicode.registrable_domain(), Some("xn--czrs0t.xn--55qx5d.cn"))
  assert_eq(unicode.normalized_domain(), ascii.normalized_domain())
  assert_eq(unicode.matched_rule(), ascii.matched_rule())
}

///|
test "IDNA adapter preserves wildcard exception and section behavior" {
  let list = parse_psl(
    "// ===BEGIN PRIVATE DOMAINS===\n*.公司.cn\n!商店.公司.cn\n// ===END PRIVATE DOMAINS===\n",
  ).unwrap()
  let exception = lookup(list, "api.商店.公司.cn").unwrap()
  assert_eq(exception.rule_kind(), @moonsuffix.ExceptionRule)
  assert_eq(exception.public_suffix(), "xn--55qx5d.cn")
  assert_eq(exception.rule_section(), Some(@moonsuffix.PrivateSection))
  let wildcard = lookup(list, "api.别的.公司.cn").unwrap()
  assert_eq(wildcard.rule_kind(), @moonsuffix.WildcardRule)
}

///|
test "IDNA errors retain input and rule line" {
  assert_true(parse_psl("com\nfoo..cn\n") is Err(InvalidRuleName(2, _, _)))
  let list = parse_psl("com").unwrap()
  assert_true(lookup(list, "foo..com") is Err(InvalidHostname(_, _)))
  assert_true(
    lookup_with_options(
      list,
      "shop.unknown",
      @moonsuffix.LookupOptions::strict_icann(),
    )
    is Err(InvalidDomain(@moonsuffix.UnlistedSuffix(_))),
  )
  assert_eq(lookup(list, "www.example.com").unwrap().public_suffix(), "com")
}
