///|
test "snapshot command parses required arguments" {
  let config = parse_snapshot_config([
    "source.psl", "snapshot.txt", "--revision", "release-1",
  ])
  assert_eq(config.source_path, "source.psl")
  assert_eq(config.output_path, "snapshot.txt")
  assert_eq(config.revision, "release-1")
  assert_true(!config.idna)
}

///|
test "snapshot command emits a deterministic verified bundle" {
  let first = build_snapshot_bundle("org\ncom\n", "revision 1", false).unwrap()
  let second = build_snapshot_bundle("com\norg\n", "revision 1", false).unwrap()
  assert_eq(first, second)
  let restored = @moonsuffix.Snapshot::restore_bundle_text(first).unwrap()
  assert_eq(restored.rule_count(), 2)
  assert_eq(restored.source_revision(), "revision 1")
  assert_eq(restored.psl_text(), "com\norg\n")
}

///|
test "snapshot command rejects malformed PSL before writing" {
  let error = build_snapshot_bundle("foo.*.com", "candidate", false)
  assert_true(error is Err(message) && message.has_prefix("invalid PSL rule"))
  assert_true(build_snapshot_bundle("com", "candidate", false) is Ok(_))
}

///|
test "IDNA snapshot mode canonicalizes Unicode rules" {
  let config = parse_snapshot_config([
    "unicode.psl", "unicode.snapshot", "--revision", "v1", "--idna",
  ])
  assert_true(config.idna)
  let unicode = build_snapshot_bundle("公司.cn\ncom\n", "v1", true).unwrap()
  let ascii = build_snapshot_bundle("xn--55qx5d.cn\ncom\n", "v1", true).unwrap()
  assert_eq(unicode, ascii)
  let restored = @moonsuffix.Snapshot::restore_bundle_text(unicode).unwrap()
  assert_eq(restored.psl_text(), "com\nxn--55qx5d.cn\n")
  let invalid = build_snapshot_bundle("com\n例子..cn\n", "v1", true)
  assert_true(invalid is Err(message) && message.contains("line 2"))
}
