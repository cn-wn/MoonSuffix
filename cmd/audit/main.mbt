///|
async fn main {
  let argv = @env.args()
  let config = parse_audit_config(argv[1:])
  let old_psl = @fs.read_file(config.old_psl_path).text()
  let new_psl = @fs.read_file(config.new_psl_path).text()
  let hosts = @fs.read_file(config.hosts_path).text()
  let outcome = if config.bundles {
    build_bundle_audit_report(old_psl, new_psl, hosts, config.strict_icann)
  } else {
    build_audit_report(
      old_psl,
      new_psl,
      hosts,
      config.from_revision.unwrap_or(""),
      config.to_revision.unwrap_or(""),
      config.strict_icann,
    )
  }
  let result = match outcome {
    Ok(value) => value
    Err(error) => fail(error)
  }
  @stdio.stdout.write(result.report)
  if config.fail_on_impact && result.changed_count > 0 {
    fail("PSL update changes \{result.changed_count} inventoried hostname(s)")
  }
}
