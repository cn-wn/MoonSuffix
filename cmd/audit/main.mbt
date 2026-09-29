///|
async fn main {
  let argv = @env.args()
  let config = parse_audit_config(argv[1:])
  let old_psl = @fs.read_file(config.old_psl_path).text()
  let new_psl = @fs.read_file(config.new_psl_path).text()
  let hosts = @fs.read_file(config.hosts_path).text()
  let cookie_inventory = match config.cookie_inventory_path {
    Some(path) => Some(@fs.read_file(path).text())
    None => None
  }
  let outcome = if config.bundles && config.idna {
    build_bundle_audit_report_with_idna(
      old_psl,
      new_psl,
      hosts,
      cookie_inventory,
      config.strict_icann,
      config.idna,
    )
  } else if config.bundles {
    build_bundle_audit_report(
      old_psl,
      new_psl,
      hosts,
      cookie_inventory,
      config.strict_icann,
    )
  } else if config.idna {
    build_audit_report_with_idna(
      old_psl,
      new_psl,
      hosts,
      cookie_inventory,
      config.from_revision.unwrap_or(""),
      config.to_revision.unwrap_or(""),
      config.strict_icann,
      config.idna,
    )
  } else {
    build_audit_report(
      old_psl,
      new_psl,
      hosts,
      cookie_inventory,
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
  if config.fail_on_impact {
    match audit_gate_error(result) {
      Some(message) => fail(message)
      None => ()
    }
  }
}
