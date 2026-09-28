///|
fn cookie_impact_snapshots() -> (@moonsuffix.Snapshot, @moonsuffix.Snapshot) {
  let old = @moonsuffix.SuffixList::parse(
      "// ===BEGIN ICANN DOMAINS===\ncom\nio\n// ===END ICANN DOMAINS===\n" +
      "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n",
    )
    .unwrap()
    .snapshot("old")
  let candidate = @moonsuffix.SuffixList::parse(
      "// ===BEGIN ICANN DOMAINS===\ncom\nio\n// ===END ICANN DOMAINS===\n" +
      "// ===BEGIN PRIVATE DOMAINS===\napp.example.com\n// ===END PRIVATE DOMAINS===\n",
    )
    .unwrap()
    .snapshot("candidate")
  (old, candidate)
}

///|
test "Cookie inventory syntax validation is independent of PSL policy" {
  let host_only = @moonsuffix.CookieScopeInput::new("WWW.Example.COM.", None)
  assert_eq(host_only.validate_syntax(), Ok(()))
  let domain = @moonsuffix.CookieScopeInput::new(
    "shop.example.com",
    Some(".EXAMPLE.COM"),
  )
  assert_eq(domain.validate_syntax(), Ok(()))
  let public_suffix = @moonsuffix.CookieScopeInput::new(
    "shop.example.com",
    Some("com"),
  )
  assert_eq(public_suffix.validate_syntax(), Ok(()))
  let mismatch = @moonsuffix.CookieScopeInput::new(
    "shop.example.com",
    Some("other.com"),
  )
  assert_eq(mismatch.validate_syntax(), Ok(()))
  assert_true(
    @moonsuffix.CookieScopeInput::new("a..example.com", None).validate_syntax()
    is Err(InvalidRequestHost(_, _)),
  )
  assert_true(
    @moonsuffix.CookieScopeInput::new("api.example.com", Some("")).validate_syntax()
    is Err(InvalidDomainAttribute(_, _)),
  )
  assert_true(
    @moonsuffix.CookieScopeInput::new("api.example.com", Some("例子.com")).validate_syntax()
    is Err(InvalidDomainAttribute(_, _)),
  )
  assert_eq(domain.validate_syntax(), Ok(()))
}

///|
test "Cookie scope audit classifies acceptance and host-only changes" {
  let (old, candidate) = cookie_impact_snapshots()
  let report = old.analyze_cookie_scope_impact(
    candidate,
    [
      @moonsuffix.CookieScopeInput::new(
        "www.app.example.com",
        Some("app.example.com"),
      ),
      @moonsuffix.CookieScopeInput::new(
        "app.example.com",
        Some("app.example.com"),
      ),
      @moonsuffix.CookieScopeInput::new("alice.github.io", Some("github.io")),
      @moonsuffix.CookieScopeInput::new("api.example.com", None),
      @moonsuffix.CookieScopeInput::new("bad..com", None),
      @moonsuffix.CookieScopeInput::new(
        "www.app.example.com",
        Some("app.example.com"),
      ),
    ],
    @moonsuffix.LookupOptions::browser_default(),
  )
  assert_eq(report.from_revision(), "old")
  assert_eq(report.to_revision(), "candidate")
  assert_eq(report.from_sha256(), old.sha256())
  assert_eq(report.to_sha256(), candidate.sha256())
  assert_eq(report.scanned_count(), 6)
  assert_eq(report.changed_count(), 4)
  assert_eq(report.unchanged_count(), 2)
  assert_eq(report.is_empty(), false)
  let impacts = report.impacts()
  assert_eq(impacts[0].index(), 0)
  assert_true(impacts[0].kind() is CookieBecameRejected)
  assert_eq(impacts[0].input().request_host(), "www.app.example.com")
  assert_eq(impacts[0].input().domain_attribute(), Some("app.example.com"))
  assert_eq(impacts[0].before().unwrap().is_host_only(), false)
  assert_true(impacts[0].after() is Err(PublicSuffixDomain("app.example.com")))
  assert_eq(impacts[1].index(), 1)
  assert_true(impacts[1].kind() is CookieScopeChanged)
  assert_eq(impacts[1].before().unwrap().domain(), "app.example.com")
  assert_eq(impacts[1].before().unwrap().is_host_only(), false)
  assert_eq(impacts[1].after().unwrap().is_host_only(), true)
  assert_eq(impacts[2].index(), 2)
  assert_true(impacts[2].kind() is CookieBecameAccepted)
  assert_true(impacts[2].before() is Err(PublicSuffixDomain("github.io")))
  assert_eq(impacts[2].after().unwrap().domain(), "github.io")
  assert_eq(impacts[3].index(), 5)
  assert_true(impacts[3].kind() is CookieBecameRejected)
}

///|
test "Cookie scope audit is deterministic and separates missing attributes" {
  let (old, candidate) = cookie_impact_snapshots()
  let inputs = [
    @moonsuffix.CookieScopeInput::new(
      "app.example.com",
      Some("app.example.com"),
    ),
  ]
  let report = old.analyze_cookie_scope_impact(
    candidate,
    inputs,
    @moonsuffix.LookupOptions::browser_default(),
  )
  assert_eq(
    report.to_csv(),
    "\"index\",\"request_host\",\"domain_attribute_present\",\"domain_attribute\",\"impact\",\"before_status\",\"before_domain\",\"before_host_only\",\"before_error\",\"after_status\",\"after_domain\",\"after_host_only\",\"after_error\"\n" +
    "\"0\",\"app.example.com\",\"true\",\"app.example.com\",\"scope_changed\",\"ok\",\"app.example.com\",\"false\",\"\",\"ok\",\"app.example.com\",\"true\",\"\"\n",
  )
  let repeat = old.analyze_cookie_scope_impact(
    candidate,
    inputs,
    @moonsuffix.LookupOptions::browser_default(),
  )
  assert_eq(report.to_csv(), repeat.to_csv())
  let unchanged = old.analyze_cookie_scope_impact(
    candidate,
    [
      @moonsuffix.CookieScopeInput::new("api.example.com", None),
      @moonsuffix.CookieScopeInput::new("api.example.com", Some("")),
    ],
    @moonsuffix.LookupOptions::browser_default(),
  )
  assert_eq(unchanged.changed_count(), 0)
  assert_eq(unchanged.unchanged_count(), 2)
  assert_eq(unchanged.is_empty(), true)
  assert_true(report.to_csv().has_prefix(unchanged.to_csv()))
  let strict_old = @moonsuffix.SuffixList::parse("com").unwrap().snapshot("v1")
  let strict_new = @moonsuffix.SuffixList::parse("com\nnet")
    .unwrap()
    .snapshot("v2")
  let missing_attribute = strict_old.analyze_cookie_scope_impact(
    strict_new,
    [@moonsuffix.CookieScopeInput::new("api.net", None)],
    @moonsuffix.LookupOptions::strict_icann(),
  )
  assert_eq(missing_attribute.changed_count(), 1)
  assert_true(
    missing_attribute
    .to_csv()
    .contains("\"0\",\"api.net\",\"false\",\"\",\"became_accepted\""),
  )
}

///|
test "Cookie scope audit isolates PRIVATE changes under ICANN-only policy" {
  let (old, candidate) = cookie_impact_snapshots()
  let report = old.analyze_cookie_scope_impact(
    candidate,
    [
      @moonsuffix.CookieScopeInput::new(
        "www.app.example.com",
        Some("app.example.com"),
      ),
      @moonsuffix.CookieScopeInput::new("alice.github.io", Some("github.io")),
    ],
    @moonsuffix.LookupOptions::new(IcannOnly, UseDefaultWildcard),
  )
  assert_eq(report.scanned_count(), 2)
  assert_eq(report.changed_count(), 0)
  assert_eq(report.unchanged_count(), 2)
}
