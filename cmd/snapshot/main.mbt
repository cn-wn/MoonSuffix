///|
async fn main {
  let argv = @env.args()
  let config = parse_snapshot_config(argv[1:])
  let source = @fs.read_file(config.source_path).text()
  let bundle = match build_snapshot_bundle(source, config.revision) {
    Ok(value) => value
    Err(error) => fail(error)
  }
  @fs.write_file(config.output_path, bundle, create_mode=CreateNew)
}
