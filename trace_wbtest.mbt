///|
test "rule trace explains wildcard and exception precedence" {
  let list = SuffixList::parse("ck\n*.ck\n!www.ck\n").unwrap()
  let trace = list.trace_lookup("a.www.ck").unwrap()
  let result = trace.outcome().unwrap()
  assert_eq(result.public_suffix(), "ck")
  assert_eq(result.matched_rule(), "!www.ck")
  let candidates = trace.candidates()
  assert_eq(candidates.length(), 4)
  assert_eq(candidates[0].rule(), "*")
  assert_eq(candidates[1].rule(), "ck")
  assert_eq(candidates[2].rule(), "*.ck")
  assert_eq(candidates[3].rule(), "!www.ck")
  assert_eq(candidates[0].is_selected(), false)
  assert_eq(candidates[2].is_selected(), false)
  assert_eq(candidates[3].is_selected(), true)
  assert_eq(candidates[3].kind(), ExceptionRule)
}

///|
test "rule trace exposes excluded private rules and selected ICANN rule" {
  let list = SuffixList::parse(
    "// ===BEGIN PRIVATE DOMAINS===\n" +
    "github.io\nio\n" +
    "// ===END PRIVATE DOMAINS===\n" +
    "// ===BEGIN ICANN DOMAINS===\n" +
    "io\n" +
    "// ===END ICANN DOMAINS===\n",
  ).unwrap()
  let browser = list.trace_lookup("user.github.io").unwrap()
  assert_eq(browser.outcome().unwrap().public_suffix(), "github.io")
  assert_eq(browser.candidates()[3].rule(), "github.io")
  assert_eq(browser.candidates()[3].is_selected(), true)
  let strict = list
    .trace_lookup_with_options("user.github.io", LookupOptions::strict_icann())
    .unwrap()
  assert_eq(strict.outcome().unwrap().public_suffix(), "io")
  let candidates = strict.candidates()
  assert_eq(candidates.length(), 4)
  assert_eq(candidates[0].rule(), "*")
  assert_eq(candidates[0].is_eligible(), false)
  assert_eq(candidates[1].section(), Some(IcannSection))
  assert_eq(candidates[1].is_selected(), true)
  assert_eq(candidates[2].section(), Some(PrivateSection))
  assert_eq(candidates[2].is_eligible(), false)
  assert_eq(candidates[3].rule(), "github.io")
  assert_eq(candidates[3].is_eligible(), false)
  assert_eq(candidates[3].is_selected(), false)
}

///|
test "rule trace preserves unknown-suffix rejection and invalid input" {
  let list = SuffixList::parse("com").unwrap()
  let browser = list.trace_lookup("shop.unknown").unwrap()
  assert_eq(browser.outcome().unwrap().matched_rule(), "*")
  assert_eq(browser.candidates().length(), 1)
  assert_eq(browser.candidates()[0].is_selected(), true)
  let strict = list
    .trace_lookup_with_options("shop.unknown", LookupOptions::strict_icann())
    .unwrap()
  assert_true(strict.outcome() is Err(UnlistedSuffix("shop.unknown")))
  assert_eq(strict.candidates().length(), 1)
  assert_eq(strict.candidates()[0].is_eligible(), false)
  assert_eq(strict.candidates()[0].is_selected(), false)
  assert_true(list.trace_lookup("a..com") is Err(EmptyLabel(1)))
  assert_eq(
    list.trace_lookup("shop.com").unwrap().outcome().unwrap().public_suffix(),
    "com",
  )
}

///|
test "rule trace excludes wildcard at its base and ignores source order" {
  let first = SuffixList::parse("*.ck\nck\n").unwrap()
  let second = SuffixList::parse("ck\n*.ck\n").unwrap()
  let base = first.trace_lookup("ck").unwrap()
  assert_eq(base.candidates().length(), 2)
  assert_eq(base.candidates()[1].rule(), "ck")
  let left = first.trace_lookup("shop.ck").unwrap().candidates()
  let right = second.trace_lookup("shop.ck").unwrap().candidates()
  assert_eq(left.length(), right.length())
  for i in 0..<left.length() {
    assert_eq(left[i].rule(), right[i].rule())
    assert_eq(left[i].section(), right[i].section())
    assert_eq(left[i].is_eligible(), right[i].is_eligible())
    assert_eq(left[i].is_selected(), right[i].is_selected())
  }
}

///|
test "trace winner agrees with ordinary lookup across rule and policy cases" {
  let list = SuffixList::parse(
    "// ===BEGIN ICANN DOMAINS===\n" +
    "com\nck\n*.ck\n!www.ck\nio\n" +
    "// ===END ICANN DOMAINS===\n" +
    "// ===BEGIN PRIVATE DOMAINS===\n" +
    "github.io\n" +
    "// ===END PRIVATE DOMAINS===\n",
  ).unwrap()
  for
    options in [LookupOptions::browser_default(), LookupOptions::strict_icann()] {
    for
      domain in [
        "shop.com", "shop.unknown", "a.b.ck", "www.ck", "a.www.ck.", "user.github.io",
      ] {
      let trace = list.trace_lookup_with_options(domain, options).unwrap()
      let ordinary = list.lookup_with_options(domain, options)
      let mut selected_count = 0
      for candidate in trace.candidates() {
        if candidate.is_selected() {
          selected_count = selected_count + 1
          assert_true(candidate.is_eligible())
        }
      }
      match (trace.outcome(), ordinary) {
        (Ok(traced), Ok(plain)) => {
          assert_eq(selected_count, 1)
          assert_eq(traced.public_suffix(), plain.public_suffix())
          assert_eq(traced.registrable_domain(), plain.registrable_domain())
          assert_eq(traced.matched_rule(), plain.matched_rule())
          assert_eq(traced.rule_section(), plain.rule_section())
        }
        (Err(traced), Err(plain)) => {
          assert_eq(selected_count, 0)
          assert_eq(traced, plain)
        }
        _ => fail("trace and ordinary lookup diverged")
      }
    }
  }
}
