///|
test "embedded source command parses arguments and normalizes Unicode" {
  let config = parse_embed_config([
    "source.psl", "embedded.mbt", "--revision", "v1", "--idna",
  ])
  assert_eq(config.source_path, "source.psl")
  assert_eq(config.output_path, "embedded.mbt")
  assert_eq(config.revision, "v1")
  assert_true(config.idna)
  let generated = build_embedded_source("公司.cn\n", "v1", true).unwrap()
  assert_true(generated.contains("xn--55qx5d.cn"))
  assert_eq(
    generated,
    build_embedded_source("xn--55qx5d.cn\n", "v1", true).unwrap(),
  )
  assert_true(
    build_embedded_source("bad..rule\n", "v1", true) is Err(message) &&
    message.contains("line 1"),
  )
}
