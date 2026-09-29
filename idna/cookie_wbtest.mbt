///|
test "Unicode Cookie scopes match equivalent A-label core behavior" {
  let list = parse_psl(
    "// ===BEGIN ICANN DOMAINS===\ncn\n公司.cn\n// ===END ICANN DOMAINS===\n",
  ).unwrap()
  let host_only = resolve_cookie_scope(list, "商店.公司.cn", None).unwrap()
  assert_eq(host_only.domain(), "xn--czrs0t.xn--55qx5d.cn")
  assert_true(host_only.is_host_only())
  let domain = resolve_cookie_scope(
    list,
    "api.商店.公司.cn",
    Some(".商店.公司.cn"),
  ).unwrap()
  assert_eq(domain.domain(), "xn--czrs0t.xn--55qx5d.cn")
  assert_true(!domain.is_host_only())
  assert_eq(
    domain,
    list
    .resolve_cookie_scope(
      "api.xn--czrs0t.xn--55qx5d.cn",
      Some(".xn--czrs0t.xn--55qx5d.cn"),
    )
    .unwrap(),
  )
  assert_eq(
    cookie_scope_matches_host(domain, "别的.商店.公司.cn"),
    Ok(true),
  )
  assert_eq(cookie_scope_matches_host(domain, "别的.公司.cn"), Ok(false))
  assert_eq(
    cookie_scope_matches_host(host_only, "api.商店.公司.cn"),
    Ok(false),
  )
  assert_eq(cookie_scope_matches_host(host_only, "商店.公司.cn"), Ok(true))
}

///|
test "Unicode Cookie Domain cannot cross the public suffix boundary" {
  let list = parse_psl("cn\n公司.cn\n").unwrap()
  assert_eq(
    resolve_cookie_scope(list, "商店.公司.cn", Some("公司.cn")),
    Err(@moonsuffix.PublicSuffixDomain("xn--55qx5d.cn")),
  )
  let public_host = resolve_cookie_scope(list, "公司.cn", Some(".公司.cn")).unwrap()
  assert_true(public_host.is_host_only())
  assert_eq(public_host.domain(), "xn--55qx5d.cn")
  assert_true(
    resolve_cookie_scope(list, "别的.公司.cn", Some("商店.公司.cn"))
    is Err(@moonsuffix.DomainMismatch(_, _)),
  )
  let scopes = shareable_cookie_scopes(list, "api.商店.公司.cn").unwrap()
  assert_eq(scopes.length(), 2)
  assert_eq(scopes[0].domain(), "api.xn--czrs0t.xn--55qx5d.cn")
  assert_eq(scopes[1].domain(), "xn--czrs0t.xn--55qx5d.cn")
  assert_eq(shareable_cookie_scopes(list, "公司.cn").unwrap().length(), 0)
}

///|
test "Unicode Cookie adapter preserves original invalid inputs" {
  let list = parse_psl("公司.cn\n").unwrap()
  assert_true(
    resolve_cookie_scope(list, "商店..公司.cn", None)
    is Err(@moonsuffix.InvalidRequestHost("商店..公司.cn", _)),
  )
  assert_true(
    resolve_cookie_scope(list, "商店.公司.cn", Some("坏..公司.cn"))
    is Err(@moonsuffix.InvalidDomainAttribute("坏..公司.cn", _)),
  )
  assert_eq(
    resolve_cookie_scope(list, "商店.公司.cn", Some("公司.cn.")),
    Err(
      @moonsuffix.InvalidDomainAttribute(
        "公司.cn.", "a trailing root dot is not permitted",
      ),
    ),
  )
  assert_true(
    cookie_scope_matches_host(
      resolve_cookie_scope(list, "商店.公司.cn", None).unwrap(),
      "坏..公司.cn",
    )
    is Err(@moonsuffix.InvalidRequestHost("坏..公司.cn", _)),
  )
  assert_true(
    shareable_cookie_scopes(list, "坏..公司.cn")
    is Err(@moonsuffix.InvalidRequestHost("坏..公司.cn", _)),
  )
}

///|
test "Unicode Cookie scope honors explicit lookup policies" {
  let list = parse_psl(
    "// ===BEGIN ICANN DOMAINS===\nio\n// ===END ICANN DOMAINS===\n" +
    "// ===BEGIN PRIVATE DOMAINS===\n公司.io\n// ===END PRIVATE DOMAINS===\n",
  ).unwrap()
  let browser = shareable_cookie_scopes(list, "shop.公司.io").unwrap()
  assert_eq(browser.length(), 1)
  let strict = shareable_cookie_scopes_with_options(
    list,
    "shop.公司.io",
    @moonsuffix.LookupOptions::strict_icann(),
  ).unwrap()
  assert_eq(strict.length(), 2)
  assert_eq(strict[1].domain(), "xn--55qx5d.io")
  assert_true(
    resolve_cookie_scope_with_options(
      list,
      "shop.公司.io",
      Some("公司.io"),
      @moonsuffix.LookupOptions::strict_icann(),
    )
    is Ok(_),
  )
  assert_true(
    resolve_cookie_scope_with_options(
      list,
      "shop.未知",
      None,
      @moonsuffix.LookupOptions::strict_icann(),
    )
    is Err(@moonsuffix.InvalidRequestHost("shop.未知", _)),
  )
}
