///|
async fn main {
  let argv = @env.args()
  let config = parse_classify_config(argv[1:])
  let bundle = @fs.read_file(config.bundle_path).text()
  let inventory = @fs.read_file(config.hosts_path).text()
  let result = match
    run_classification(bundle, inventory, config.strict_icann) {
    Ok(value) => value
    Err(error) => fail(error)
  }
  @stdio.stdout.write(result.report)
  if config.fail_on_error {
    match classification_gate_error(result) {
      Some(message) => fail(message)
      None => ()
    }
  }
}
