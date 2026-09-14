///|
fn official_semantics_fixture() -> SuffixList {
  SuffixList::parse(
    (
      #|// compact fixture derived from the upstream CC0 semantic cases
      #|biz
      #|com
      #|uk.com
      #|ac
      #|*.mm
      #|jp
      #|ac.jp
      #|kyoto.jp
      #|ide.kyoto.jp
      #|*.kobe.jp
      #|!city.kobe.jp
      #|*.ck
      #|!www.ck
      #|公司.cn
      #|
    ),
  ).unwrap()
}

///|
fn sectioned_fixture() -> SuffixList {
  SuffixList::parse(
    (
      #|// ===BEGIN ICANN DOMAINS===
      #|com
      #|io
      #|// ===END ICANN DOMAINS===
      #|// ===BEGIN PRIVATE DOMAINS===
      #|github.io
      #|// ===END PRIVATE DOMAINS===
      #|
    ),
  ).unwrap()
}

///|
test "parse comments whitespace and duplicate rules deterministically" {
  let suffixes = SuffixList::parse(
    (
      #| // comment
      #|com trailing-comment
      #|org	owner
      #|com
      #|
    ),
  ).unwrap()
  assert_eq(suffixes.rule_count(), 2)
  assert_eq(suffixes.node_count(), 3)
}

///|
test "reject malformed rule syntax and recover on the next parse" {
  assert_true(SuffixList::parse("foo.*.com") is Err(_))
  assert_true(SuffixList::parse("*foo.com") is Err(_))
  assert_true(SuffixList::parse(".com") is Err(_))
  assert_true(SuffixList::parse("!") is Err(_))
  let valid = SuffixList::parse("com").unwrap()
  assert_eq(valid.public_suffix("www.example.com").unwrap(), "com")
}

///|
test "parse PSL section markers strictly and recover after errors" {
  assert_true(
    SuffixList::parse(
      "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END PRIVATE DOMAINS===",
    )
    is Err(_),
  )
  assert_true(
    SuffixList::parse(
      "// ===BEGIN ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===",
    )
    is Err(_),
  )
  assert_true(
    SuffixList::parse("// ===BEGIN PRIVATE DOMAINS===\ngithub.io") is Err(_),
  )
  let valid = sectioned_fixture()
  assert_eq(valid.rule_count(), 3)
}

///|
test "browser and ICANN-only scopes select different prevailing rules" {
  let suffixes = sectioned_fixture()
  let browser = suffixes.lookup("user.github.io").unwrap()
  assert_eq(browser.public_suffix(), "github.io")
  assert_eq(browser.registrable_domain(), Some("user.github.io"))
  assert_eq(browser.rule_section(), Some(PrivateSection))
  let icann = suffixes
    .lookup_with_options(
      "user.github.io",
      LookupOptions::new(IcannOnly, UseDefaultWildcard),
    )
    .unwrap()
  assert_eq(icann.public_suffix(), "io")
  assert_eq(icann.registrable_domain(), Some("github.io"))
  assert_eq(icann.rule_section(), Some(IcannSection))
}

///|
test "strict policy rejects unknown suffixes while defaults remain compatible" {
  let suffixes = sectioned_fixture()
  assert_eq(suffixes.lookup("service.internal").unwrap().matched_rule(), "*")
  assert_eq(suffixes.lookup("service.internal").unwrap().rule_section(), None)
  assert_true(
    suffixes.lookup_with_options(
      "service.internal",
      LookupOptions::strict_icann(),
    )
    is Err(UnlistedSuffix("service.internal")),
  )
}

///|
test "unsectioned custom rules stay eligible in ICANN-only mode" {
  let suffixes = SuffixList::parse("internal").unwrap()
  let result = suffixes
    .lookup_with_options("api.service.internal", LookupOptions::strict_icann())
    .unwrap()
  assert_eq(result.public_suffix(), "internal")
  assert_eq(result.rule_section(), Some(UnsectionedRule))
}

///|
test "serialize PSL text in a stable canonical order" {
  let suffixes = SuffixList::parse(
    (
      #|z.local trailing-field
      #|*.local
      #|z.local
      #|// ===BEGIN ICANN DOMAINS===
      #|org
      #|com
      #|*.kobe.jp
      #|!city.kobe.jp
      #|// ===END ICANN DOMAINS===
      #|// ===BEGIN PRIVATE DOMAINS===
      #|github.io
      #|blogspot.com
      #|// ===END PRIVATE DOMAINS===
      #|
    ),
  ).unwrap()
  assert_eq(
    suffixes.to_psl_text(),
    (
      #|*.local
      #|z.local
      #|
      #|// ===BEGIN ICANN DOMAINS===
      #|!city.kobe.jp
      #|*.kobe.jp
      #|com
      #|org
      #|// ===END ICANN DOMAINS===
      #|
      #|// ===BEGIN PRIVATE DOMAINS===
      #|blogspot.com
      #|github.io
      #|// ===END PRIVATE DOMAINS===
      #|
    ),
  )
  let reordered = SuffixList::parse(
    (
      #|*.local
      #|z.local
      #|// ===BEGIN ICANN DOMAINS===
      #|!city.kobe.jp
      #|*.kobe.jp
      #|com
      #|org
      #|// ===END ICANN DOMAINS===
      #|// ===BEGIN PRIVATE DOMAINS===
      #|blogspot.com
      #|github.io
      #|// ===END PRIVATE DOMAINS===
      #|
    ),
  ).unwrap()
  assert_eq(reordered.to_psl_text(), suffixes.to_psl_text())
}

///|
test "serialized rule sets round trip without semantic or byte drift" {
  let original = SuffixList::parse(
    (
      #|custom
      #|// ===BEGIN ICANN DOMAINS===
      #|com
      #|*.ck
      #|!www.ck
      #|// ===END ICANN DOMAINS===
      #|// ===BEGIN PRIVATE DOMAINS===
      #|com
      #|github.io
      #|// ===END PRIVATE DOMAINS===
      #|
    ),
  ).unwrap()
  let canonical = original.to_psl_text()
  let restored = SuffixList::parse(canonical).unwrap()
  assert_eq(restored.rule_count(), original.rule_count())
  assert_eq(restored.to_psl_text(), canonical)
  for domain in ["api.custom", "www.www.ck", "user.github.io", "unknown"] {
    let before = original.lookup(domain).unwrap()
    let after = restored.lookup(domain).unwrap()
    assert_eq(after.public_suffix(), before.public_suffix())
    assert_eq(after.registrable_domain(), before.registrable_domain())
    assert_eq(after.matched_rule(), before.matched_rule())
    assert_eq(after.rule_section(), before.rule_section())
  }
}

///|
test "empty rule sets serialize and round trip as empty text" {
  let empty = SuffixList::parse("").unwrap()
  assert_eq(empty.to_psl_text(), "")
  assert_eq(SuffixList::parse(empty.to_psl_text()).unwrap().rule_count(), 0)
}

///|
test "snapshot binds canonical Unicode PSL bytes to provenance" {
  let first = SuffixList::parse("公司.cn\ncom").unwrap()
  let reordered = SuffixList::parse("com\n公司.cn").unwrap()
  let snapshot = first.snapshot("release 2026/09")
  assert_eq(snapshot.source_revision(), "release 2026/09")
  assert_eq(snapshot.psl_text(), "com\n公司.cn\n")
  assert_eq(snapshot.rule_count(), 2)
  assert_eq(
    snapshot.sha256(),
    "9562f01cbb016548123eacc23538f909a6c383572887adc18cd8bb1009685e69",
  )
  assert_eq(reordered.snapshot("other").sha256(), snapshot.sha256())
  assert_eq(
    snapshot.manifest_text(),
    (
      #|format=moonsuffix-snapshot-v1
      #|source_revision=release%202026%2f09
      #|psl_sha256=9562f01cbb016548123eacc23538f909a6c383572887adc18cd8bb1009685e69
      #|rule_count=2
      #|
    ),
  )
}

///|
test "snapshot digest changes when canonical rules change" {
  let before = SuffixList::parse("com").unwrap().snapshot("same")
  let after = SuffixList::parse("com\norg").unwrap().snapshot("same")
  assert_true(before.sha256() != after.sha256())
}

///|
test "restore verifies and round trips a stored snapshot" {
  let original = SuffixList::parse("公司.cn\ncom")
    .unwrap()
    .snapshot("release 2026/秋")
  let restored = Snapshot::restore(
    original.psl_text(),
    original.manifest_text(),
  ).unwrap()
  assert_eq(restored.source_revision(), original.source_revision())
  assert_eq(restored.psl_text(), original.psl_text())
  assert_eq(restored.sha256(), original.sha256())
  assert_eq(restored.rule_count(), original.rule_count())
  assert_eq(restored.manifest_text(), original.manifest_text())
}

///|
test "restore rejects malformed and noncanonical snapshot inputs" {
  let snapshot = SuffixList::parse("com\norg").unwrap().snapshot("v1")
  assert_true(
    Snapshot::restore(snapshot.psl_text(), snapshot.manifest_text() + "extra")
    is Err(InvalidManifest("expected four LF-terminated fields")),
  )
  assert_true(
    Snapshot::restore(
      snapshot.psl_text(),
      "format=other\nsource_revision=v1\npsl_sha256=0000000000000000000000000000000000000000000000000000000000000000\nrule_count=2\n",
    )
    is Err(InvalidManifest("unsupported format")),
  )
  assert_true(
    Snapshot::restore(
      snapshot.psl_text(),
      "format=moonsuffix-snapshot-v1\nsource_revision=%ff\npsl_sha256=0000000000000000000000000000000000000000000000000000000000000000\nrule_count=2\n",
    )
    is Err(InvalidRevisionEncoding),
  )
  assert_true(
    Snapshot::restore(
      snapshot.psl_text(),
      "format=moonsuffix-snapshot-v1\nsource_revision=v1\npsl_sha256=ABC\nrule_count=2\n",
    )
    is Err(InvalidDigest("ABC")),
  )
  assert_true(
    Snapshot::restore(
      "foo.*.com\n", "format=moonsuffix-snapshot-v1\nsource_revision=v1\npsl_sha256=0000000000000000000000000000000000000000000000000000000000000000\nrule_count=0\n",
    )
    is Err(InvalidSnapshotRules(_)),
  )
  assert_true(
    Snapshot::restore("org\ncom\n", snapshot.manifest_text())
    is Err(NonCanonicalPsl),
  )
}

///|
test "restore detects digest and rule count tampering" {
  let snapshot = SuffixList::parse("com\norg").unwrap().snapshot("v1")
  let wrong_digest = "format=moonsuffix-snapshot-v1\n" +
    "source_revision=v1\n" +
    "psl_sha256=0000000000000000000000000000000000000000000000000000000000000000\n" +
    "rule_count=2\n"
  assert_true(
    Snapshot::restore(snapshot.psl_text(), wrong_digest)
    is Err(DigestMismatch(_, _)),
  )
  let wrong_count = "format=moonsuffix-snapshot-v1\n" +
    "source_revision=v1\n" +
    "psl_sha256=\{snapshot.sha256()}\n" +
    "rule_count=3\n"
  assert_true(
    Snapshot::restore(snapshot.psl_text(), wrong_count)
    is Err(RuleCountMismatch(3, 2)),
  )
  let malformed_count = "format=moonsuffix-snapshot-v1\n" +
    "source_revision=v1\n" +
    "psl_sha256=\{snapshot.sha256()}\n" +
    "rule_count=02\n"
  assert_true(
    Snapshot::restore(snapshot.psl_text(), malformed_count)
    is Err(InvalidRuleCount("02")),
  )
}

///|
test "snapshot diff classifies additions removals and section moves" {
  let before = SuffixList::parse(
      (
        #|local
        #|// ===BEGIN ICANN DOMAINS===
        #|com
        #|org
        #|// ===END ICANN DOMAINS===
        #|// ===BEGIN PRIVATE DOMAINS===
        #|github.io
        #|old.private
        #|// ===END PRIVATE DOMAINS===
        #|
      ),
    )
    .unwrap()
    .snapshot("v1")
  let after = SuffixList::parse(
      (
        #|local
        #|// ===BEGIN ICANN DOMAINS===
        #|com
        #|github.io
        #|net
        #|// ===END ICANN DOMAINS===
        #|// ===BEGIN PRIVATE DOMAINS===
        #|new.private
        #|// ===END PRIVATE DOMAINS===
        #|
      ),
    )
    .unwrap()
    .snapshot("v2 candidate")
  let diff = before.diff(after)
  assert_eq(diff.from_revision(), "v1")
  assert_eq(diff.to_revision(), "v2 candidate")
  assert_eq(diff.from_sha256(), before.sha256())
  assert_eq(diff.to_sha256(), after.sha256())
  assert_eq(diff.added_count(), 2)
  assert_eq(diff.removed_count(), 2)
  assert_eq(diff.moved_count(), 1)
  assert_eq(diff.is_empty(), false)
  let changes = diff.changes()
  assert_eq(changes.length(), 5)
  assert_eq(changes[0], MovedRule("github.io", PrivateSection, IcannSection))
  assert_eq(changes[1], AddedRule("net", IcannSection))
  assert_eq(changes[2], AddedRule("new.private", PrivateSection))
  assert_eq(changes[3], RemovedRule("old.private", PrivateSection))
  assert_eq(changes[4], RemovedRule("org", IcannSection))
  assert_eq(
    diff.report_text(),
    "format=moonsuffix-diff-v1\n" +
    "from_revision=v1\n" +
    "to_revision=v2%20candidate\n" +
    "from_sha256=\{before.sha256()}\n" +
    "to_sha256=\{after.sha256()}\n" +
    "added=2\nremoved=2\nmoved=1\nchanges:\n" +
    "> [PRIVATE->ICANN] github.io\n" +
    "+ [ICANN] net\n" +
    "+ [PRIVATE] new.private\n" +
    "- [PRIVATE] old.private\n" +
    "- [ICANN] org\n",
  )
}

///|
test "identical canonical snapshots have an empty semantic diff" {
  let rules = SuffixList::parse("com\norg").unwrap()
  let diff = rules.snapshot("old").diff(rules.snapshot("new"))
  assert_eq(diff.is_empty(), true)
  assert_eq(diff.changes().length(), 0)
  assert_eq(diff.added_count(), 0)
  assert_eq(diff.removed_count(), 0)
  assert_eq(diff.moved_count(), 0)
}

///|
test "multi-section membership changes are not misreported as moves" {
  let before = SuffixList::parse(
      (
        #|// ===BEGIN ICANN DOMAINS===
        #|com
        #|// ===END ICANN DOMAINS===
        #|// ===BEGIN PRIVATE DOMAINS===
        #|com
        #|// ===END PRIVATE DOMAINS===
        #|
      ),
    )
    .unwrap()
    .snapshot("before")
  let after = SuffixList::parse(
      (
        #|// ===BEGIN PRIVATE DOMAINS===
        #|com
        #|// ===END PRIVATE DOMAINS===
        #|
      ),
    )
    .unwrap()
    .snapshot("after")
  let diff = before.diff(after)
  assert_eq(diff.changes().length(), 1)
  assert_eq(diff.changes()[0], RemovedRule("com", IcannSection))
  assert_eq(diff.removed_count(), 1)
  assert_eq(diff.moved_count(), 0)
}

///|
test "batch lookup preserves order and recovers after row errors" {
  let suffixes = sectioned_fixture()
  let report = suffixes.lookup_batch_with_options(
    ["WWW.Example.COM.", "a..com", "service.internal", "bad,\" domain"],
    LookupOptions::strict_icann(),
  )
  assert_eq(report.length(), 4)
  assert_eq(report.success_count(), 1)
  assert_eq(report.error_count(), 3)
  let items = report.items()
  assert_eq(items[0].index(), 0)
  assert_eq(items[0].input(), "WWW.Example.COM.")
  match items[0].result() {
    Ok(result) => {
      assert_eq(result.normalized_domain(), "www.example.com.")
      assert_eq(result.public_suffix(), "com.")
    }
    Err(_) => fail("first batch row should succeed")
  }
  assert_true(items[1].result() is Err(EmptyLabel(1)))
  assert_true(items[2].result() is Err(UnlistedSuffix("service.internal")))
  assert_true(items[3].result() is Err(InvalidDomainCharacter(0, ' ')))
  assert_eq(
    report.to_csv(),
    (
      #|"index","input","status","normalized_domain","public_suffix","registrable_domain","matched_rule","rule_kind","rule_section","error"
      #|"0","WWW.Example.COM.","ok","www.example.com.","com.","example.com.","com","exact","ICANN",""
      #|"1","a..com","error","","","","","","","domain contains an empty label at index 1"
      #|"2","service.internal","error","","","","","","","domain 'service.internal' has no suffix listed by the selected policy"
      #|"3","bad,"" domain","error","","","","","","","domain label 0 contains invalid character ' '"
      #|
    ),
  )
}

///|
test "browser-default batch keeps unknown suffix behavior" {
  let report = sectioned_fixture().lookup_batch(["service.internal"])
  assert_eq(report.success_count(), 1)
  match report.items()[0].result() {
    Ok(result) => assert_eq(result.matched_rule(), "*")
    Err(_) => fail("browser-default batch row should succeed")
  }
}

///|
test "snapshot impact reports only externally visible hostname changes" {
  let before = SuffixList::parse(
      (
        #|meta
        #|// ===BEGIN ICANN DOMAINS===
        #|com
        #|old
        #|uk
        #|// ===END ICANN DOMAINS===
        #|
      ),
    )
    .unwrap()
    .snapshot("v1")
  let after = SuffixList::parse(
      (
        #|// ===BEGIN ICANN DOMAINS===
        #|com
        #|new
        #|co.uk
        #|meta
        #|// ===END ICANN DOMAINS===
        #|
      ),
    )
    .unwrap()
    .snapshot("v2")
  let report = before.analyze_impact(
    after,
    ["api.new", "api.old", "shop.example.co.uk", "api.meta", "api.com"],
    LookupOptions::strict_icann(),
  )
  assert_eq(report.from_revision(), "v1")
  assert_eq(report.to_revision(), "v2")
  assert_eq(report.from_sha256(), before.sha256())
  assert_eq(report.to_sha256(), after.sha256())
  assert_eq(report.scanned_count(), 5)
  assert_eq(report.changed_count(), 4)
  assert_eq(report.unchanged_count(), 1)
  assert_eq(report.is_empty(), false)
  let impacts = report.impacts()
  assert_eq(impacts[0].index(), 0)
  assert_eq(impacts[0].input(), "api.new")
  assert_eq(impacts[0].kind(), BecameAccepted)
  assert_true(impacts[0].before() is Err(UnlistedSuffix("api.new")))
  assert_true(impacts[0].after() is Ok(_))
  assert_eq(impacts[1].kind(), BecameRejected)
  assert_eq(impacts[2].kind(), BoundaryChanged)
  assert_eq(impacts[3].kind(), RuleMetadataChanged)
  assert_true(report.to_csv().contains("\"0\",\"api.new\",\"became_accepted\""))
  assert_true(
    report.to_csv().contains("\"3\",\"api.meta\",\"rule_metadata_changed\""),
  )
  assert_eq(report.to_csv().contains("api.com"), false)
}

///|
test "snapshot impact preserves changed duplicates and handles empty input" {
  let before = SuffixList::parse("com").unwrap().snapshot("before")
  let after = SuffixList::parse("com\nnet").unwrap().snapshot("after")
  let duplicates = before.analyze_impact(
    after,
    ["api.net", "api.net"],
    LookupOptions::strict_icann(),
  )
  assert_eq(duplicates.changed_count(), 2)
  assert_eq(duplicates.impacts()[0].index(), 0)
  assert_eq(duplicates.impacts()[1].index(), 1)
  let empty = before.analyze_impact(after, [], LookupOptions::strict_icann())
  assert_eq(empty.scanned_count(), 0)
  assert_eq(empty.changed_count(), 0)
  assert_eq(empty.unchanged_count(), 0)
  assert_eq(empty.is_empty(), true)
  assert_eq(
    empty.to_csv(),
    "\"index\",\"input\",\"impact\",\"before_status\",\"before_normalized_domain\",\"before_public_suffix\",\"before_registrable_domain\",\"before_matched_rule\",\"before_rule_kind\",\"before_rule_section\",\"before_error\",\"after_status\",\"after_normalized_domain\",\"after_public_suffix\",\"after_registrable_domain\",\"after_matched_rule\",\"after_rule_kind\",\"after_rule_section\",\"after_error\"\n",
  )
}

///|
test "site keys compare registrable hostname boundaries" {
  let suffixes = sectioned_fixture()
  assert_eq(suffixes.site_key("WWW.Example.COM."), Ok("example.com"))
  assert_eq(
    suffixes.same_registrable_site("www.example.com", "api.example.com."),
    Ok(true),
  )
  assert_eq(
    suffixes.same_registrable_site("www.example.com", "api.example.io"),
    Ok(false),
  )
}

///|
test "private suffixes split sites unless policy excludes them" {
  let suffixes = sectioned_fixture()
  assert_eq(
    suffixes.same_registrable_site("alice.github.io", "bob.github.io"),
    Ok(false),
  )
  assert_eq(
    suffixes.same_registrable_site_with_options(
      "alice.github.io",
      "bob.github.io",
      LookupOptions::new(IcannOnly, UseDefaultWildcard),
    ),
    Ok(true),
  )
}

///|
test "site keys reject public suffixes invalid domains and strict unknowns" {
  let suffixes = sectioned_fixture()
  assert_eq(suffixes.site_key("com"), Err(NoRegistrableDomain("com")))
  assert_eq(suffixes.site_key("a..com"), Err(InvalidSiteDomain(EmptyLabel(1))))
  assert_eq(
    suffixes.site_key_with_options(
      "service.internal",
      LookupOptions::strict_icann(),
    ),
    Err(InvalidSiteDomain(UnlistedSuffix("service.internal"))),
  )
  assert_eq(
    SiteError::NoRegistrableDomain("com").message(),
    "domain 'com' is a public suffix and has no registrable site",
  )
}

///|
test "implicit wildcard handles unlisted suffixes" {
  let suffixes = official_semantics_fixture()
  let one = suffixes.lookup("example").unwrap()
  assert_eq(one.public_suffix(), "example")
  assert_eq(one.registrable_domain(), None)
  assert_eq(one.rule_kind(), DefaultRule)
  let two = suffixes.lookup("b.example.example").unwrap()
  assert_eq(two.public_suffix(), "example")
  assert_eq(two.registrable_domain(), Some("example.example"))
  assert_eq(two.matched_rule(), "*")
}

///|
test "exact rules choose the greatest label count" {
  let suffixes = official_semantics_fixture()
  assert_eq(suffixes.registrable_domain("biz").unwrap(), None)
  assert_eq(
    suffixes.registrable_domain("a.b.domain.biz").unwrap(),
    Some("domain.biz"),
  )
  let uk = suffixes.lookup("a.example.uk.com").unwrap()
  assert_eq(uk.public_suffix(), "uk.com")
  assert_eq(uk.registrable_domain(), Some("example.uk.com"))
  assert_eq(uk.rule_kind(), ExactRule)
}

///|
test "wildcard consumes one label and does not imply its base" {
  let suffixes = official_semantics_fixture()
  let base = suffixes.lookup("mm").unwrap()
  assert_eq(base.rule_kind(), DefaultRule)
  assert_eq(suffixes.registrable_domain("c.mm").unwrap(), None)
  let nested = suffixes.lookup("a.b.c.mm").unwrap()
  assert_eq(nested.public_suffix(), "c.mm")
  assert_eq(nested.registrable_domain(), Some("b.c.mm"))
  assert_eq(nested.matched_rule(), "*.mm")
}

///|
test "exception rules override wildcard matches" {
  let suffixes = official_semantics_fixture()
  assert_eq(suffixes.registrable_domain("test.ck").unwrap(), None)
  assert_eq(
    suffixes.registrable_domain("a.b.test.ck").unwrap(),
    Some("b.test.ck"),
  )
  let exception = suffixes.lookup("www.www.ck").unwrap()
  assert_eq(exception.public_suffix(), "ck")
  assert_eq(exception.registrable_domain(), Some("www.ck"))
  assert_eq(exception.matched_rule(), "!www.ck")
  assert_eq(exception.rule_kind(), ExceptionRule)
}

///|
test "complex exception shortens the prevailing rule" {
  let suffixes = official_semantics_fixture()
  assert_eq(suffixes.registrable_domain("c.kobe.jp").unwrap(), None)
  let city = suffixes.lookup("www.city.kobe.jp").unwrap()
  assert_eq(city.public_suffix(), "kobe.jp")
  assert_eq(city.registrable_domain(), Some("city.kobe.jp"))
}

///|
test "case normalization and one trailing root dot are preserved" {
  let suffixes = official_semantics_fixture()
  let result = suffixes.lookup("WwW.Example.COM.").unwrap()
  assert_eq(result.normalized_domain(), "www.example.com.")
  assert_eq(result.public_suffix(), "com.")
  assert_eq(result.registrable_domain(), Some("example.com."))
  assert_eq(result.matched_rule(), "com")
}

///|
test "unicode labels work when list and lookup use the same representation" {
  let suffixes = official_semantics_fixture()
  let result = suffixes.lookup("商店.公司.CN").unwrap()
  assert_eq(result.public_suffix(), "公司.cn")
  assert_eq(result.registrable_domain(), Some("商店.公司.cn"))
}

///|
test "reject empty labels and PSL metacharacters in domains" {
  let suffixes = official_semantics_fixture()
  assert_true(suffixes.lookup("") is Err(EmptyDomain))
  assert_true(suffixes.lookup(".example.com") is Err(EmptyLabel(0)))
  assert_true(suffixes.lookup("a..com") is Err(EmptyLabel(1)))
  assert_true(suffixes.lookup("example.com..") is Err(EmptyLabel(2)))
  assert_true(suffixes.lookup("*.example.com") is Err(_))
}

///|
test "focused convenience queries agree with lookup" {
  let suffixes = official_semantics_fixture()
  let result = suffixes.lookup("api.example.com").unwrap()
  assert_eq(
    suffixes.public_suffix("api.example.com").unwrap(),
    result.public_suffix(),
  )
  assert_eq(
    suffixes.registrable_domain("api.example.com").unwrap(),
    result.registrable_domain(),
  )
  assert_eq(suffixes.is_public_suffix("com").unwrap(), true)
  assert_eq(suffixes.is_public_suffix("example.com").unwrap(), false)
}
