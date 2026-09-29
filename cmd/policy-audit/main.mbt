///|
async fn main {
  let argv = @env.args()
  let config = parse_policy_audit_config(argv[1:])
  let bundle = @fs.read_file(config.bundle_path).text()
  let inventory = @fs.read_file(config.hosts_path).text()
  let result = match run_policy_audit(bundle, inventory, config.idna) {
    Ok(value) => value
    Err(error) => fail(error)
  }
  @stdio.stdout.write(result.report)
  if config.fail_on_impact {
    match policy_audit_gate_error(result) {
      Some(message) => fail(message)
      None => ()
    }
  }
}
