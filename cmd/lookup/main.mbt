///|
async fn main {
  let argv = @env.args()
  let config = parse_lookup_config(argv[1:])
  let bundle = @fs.read_file(config.bundle_path).text()
  let report = match
    query_bundle(bundle, config.hostname, config.idna, config.strict_icann) {
    Ok(value) => value
    Err(error) => fail(error)
  }
  @stdio.stdout.write(report)
}
