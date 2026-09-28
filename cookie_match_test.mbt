///|
test "host-only cookie matches only its canonical origin host" {
  let list = @moonsuffix.SuffixList::parse("com").unwrap()
  let scope = list.resolve_cookie_scope("WWW.Example.COM.", None).unwrap()
  assert_eq(scope.matches_host("www.example.com"), Ok(true))
  assert_eq(scope.matches_host("WWW.EXAMPLE.COM."), Ok(true))
  assert_eq(scope.matches_host("api.www.example.com"), Ok(false))
  assert_eq(scope.matches_host("example.com"), Ok(false))
}

///|
test "Domain cookie matches its parent and descendants at label boundaries" {
  let list = @moonsuffix.SuffixList::parse("com").unwrap()
  let scope = list
    .resolve_cookie_scope("shop.example.com", Some(".EXAMPLE.COM"))
    .unwrap()
  assert_eq(scope.matches_host("example.com"), Ok(true))
  assert_eq(scope.matches_host("a.b.example.com."), Ok(true))
  assert_eq(scope.matches_host("badexample.com"), Ok(false))
  assert_eq(scope.matches_host("example.com.evil"), Ok(false))
  assert_eq(scope.matches_host("com"), Ok(false))
}

///|
test "public-suffix exception stays host-only and rejects invalid targets" {
  let list = @moonsuffix.SuffixList::parse("com").unwrap()
  let scope = list.resolve_cookie_scope("COM", Some("com")).unwrap()
  assert_eq(scope.is_host_only(), true)
  assert_eq(scope.matches_host("com"), Ok(true))
  assert_eq(scope.matches_host("other.com"), Ok(false))
  assert_true(scope.matches_host("a..com") is Err(InvalidRequestHost(_, _)))
  assert_true(scope.matches_host("例子.com") is Err(InvalidRequestHost(_, _)))
  assert_eq(scope.matches_host("shop.com"), Ok(false))
}

///|
test "private suffixes keep independently scoped Cookie domains" {
  let list = @moonsuffix.SuffixList::parse(
    "// ===BEGIN ICANN DOMAINS===\nio\n// ===END ICANN DOMAINS===\n" +
    "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n",
  ).unwrap()
  let alice = list
    .resolve_cookie_scope("www.alice.github.io", Some("alice.github.io"))
    .unwrap()
  assert_eq(alice.matches_host("api.alice.github.io"), Ok(true))
  assert_eq(alice.matches_host("bob.github.io"), Ok(false))
}
