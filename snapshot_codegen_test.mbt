///|
test "generated MoonBit source is deterministic and contains a verified bundle" {
  let list = @moonsuffix.SuffixList::parse("com\n*.ck\n!www.ck\n").unwrap()
  let snapshot = list.snapshot("revision with quote \" and slash \\")
  let source = snapshot.to_moonbit_source()
  assert_eq(source, snapshot.to_moonbit_source())
  assert_true(source.contains("pub fn embedded_suffix_snapshot()"))
  assert_true(source.contains("@moonsuffix.Snapshot::restore_bundle_text"))
  assert_true(source.contains("Canonical PSL SHA-256: \{snapshot.sha256()}"))
  assert_true(source.contains("format=moonsuffix-snapshot-v1\\n"))
  assert_true(source.contains("source_revision=revision%20with%20quote"))
  assert_true(source.contains("!www.ck\\n"))
}
