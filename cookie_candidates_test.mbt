///|
test "shareable Cookie scopes stop at the registrable boundary" {
  let list = @moonsuffix.SuffixList::parse("com\n").unwrap()
  let scopes = list.shareable_cookie_scopes("Api.Shop.Example.COM.").unwrap()
  assert_eq(scopes.length(), 3)
  assert_eq(scopes[0].domain(), "api.shop.example.com")
  assert_eq(scopes[1].domain(), "shop.example.com")
  assert_eq(scopes[2].domain(), "example.com")
  for scope in scopes {
    assert_true(!scope.is_host_only())
    assert_eq(
      list.resolve_cookie_scope("api.shop.example.com", Some(scope.domain())),
      Ok(scope),
    )
    assert_eq(scope.matches_host("api.shop.example.com"), Ok(true))
  }
  assert_eq(
    list.resolve_cookie_scope("api.shop.example.com", Some("com")),
    Err(PublicSuffixDomain("com")),
  )
  assert_eq(list.shareable_cookie_scopes("COM").unwrap().length(), 0)
  assert_eq(list.shareable_cookie_scopes("com").unwrap().length(), 0)
  assert_eq(
    scopes,
    list.shareable_cookie_scopes("api.shop.example.com").unwrap(),
  )
}

///|
test "PRIVATE rules and policy selection change Cookie sharing boundary" {
  let list = @moonsuffix.SuffixList::parse(
    "// ===BEGIN ICANN DOMAINS===\nio\n// ===END ICANN DOMAINS===\n" +
    "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n",
  ).unwrap()
  let browser = list.shareable_cookie_scopes("www.alice.github.io").unwrap()
  assert_eq(browser.length(), 2)
  assert_eq(browser[0].domain(), "www.alice.github.io")
  assert_eq(browser[1].domain(), "alice.github.io")
  assert_eq(list.shareable_cookie_scopes("github.io").unwrap().length(), 0)
  let icann = list
    .shareable_cookie_scopes_with_options(
      "www.alice.github.io",
      @moonsuffix.LookupOptions::strict_icann(),
    )
    .unwrap()
  assert_eq(icann.length(), 3)
  assert_eq(icann[2].domain(), "github.io")
  assert_eq(
    list.shareable_cookie_scopes("www.bob.github.io").unwrap()[1].domain(),
    "bob.github.io",
  )
}

///|
test "wildcard and exception rules give distinct sharing limits" {
  let list = @moonsuffix.SuffixList::parse("*.ck\n!www.ck\n").unwrap()
  let wildcard = list.shareable_cookie_scopes("x.y.ck").unwrap()
  assert_eq(wildcard.length(), 1)
  assert_eq(wildcard[0].domain(), "x.y.ck")
  let exception = list.shareable_cookie_scopes("api.www.ck").unwrap()
  assert_eq(exception.length(), 2)
  assert_eq(exception[0].domain(), "api.www.ck")
  assert_eq(exception[1].domain(), "www.ck")
  assert_eq(list.shareable_cookie_scopes("y.ck").unwrap().length(), 0)
}

///|
test "shareable Cookie scope enumeration rejects invalid or unlisted hosts" {
  let list = @moonsuffix.SuffixList::parse("com\n").unwrap()
  assert_true(
    list.shareable_cookie_scopes("a..com") is Err(InvalidRequestHost(_, _)),
  )
  assert_true(
    list.shareable_cookie_scopes("例子.com") is Err(InvalidRequestHost(_, _)),
  )
  assert_true(
    list.shareable_cookie_scopes_with_options(
      "api.unknown",
      @moonsuffix.LookupOptions::strict_icann(),
    )
    is Err(InvalidRequestHost(_, _)),
  )
  assert_eq(
    list.shareable_cookie_scopes("shop.example.com").unwrap().length(),
    2,
  )
}
