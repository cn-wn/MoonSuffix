///|
test "snapshot command parses required arguments" {
  let config = parse_snapshot_config([
    "source.psl", "snapshot.txt", "--revision", "release-1",
  ])
  assert_eq(config.source_path, "source.psl")
  assert_eq(config.output_path, "snapshot.txt")
  assert_eq(config.revision, "release-1")
}

///|
test "snapshot command emits a deterministic verified bundle" {
  let first = build_snapshot_bundle("org\ncom\n", "revision 1").unwrap()
  let second = build_snapshot_bundle("com\norg\n", "revision 1").unwrap()
  assert_eq(first, second)
  let restored = @moonsuffix.Snapshot::restore_bundle_text(first).unwrap()
  assert_eq(restored.rule_count(), 2)
  assert_eq(restored.source_revision(), "revision 1")
  assert_eq(restored.psl_text(), "com\norg\n")
}

///|
test "snapshot command rejects malformed PSL before writing" {
  let error = build_snapshot_bundle("foo.*.com", "candidate")
  assert_true(error is Err(message) && message.has_prefix("invalid PSL rule"))
  assert_true(build_snapshot_bundle("com", "candidate") is Ok(_))
}
