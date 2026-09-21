///|
async fn main {
  let argv = @env.args()
  let config = parse_audit_config(argv[1:])
  let old_psl = @fs.read_file(config.old_psl_path).text()
  let new_psl = @fs.read_file(config.new_psl_path).text()
  let hosts = @fs.read_file(config.hosts_path).text()
  let report = match
    build_audit_report(
      old_psl,
      new_psl,
      hosts,
      config.from_revision,
      config.to_revision,
      config.strict_icann,
    ) {
    Ok(value) => value
    Err(error) => fail(error)
  }
  @stdio.stdout.write(report)
}
