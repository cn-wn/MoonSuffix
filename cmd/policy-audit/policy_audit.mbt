///|
struct PolicyAuditConfig {
  bundle_path : String
  hosts_path : String
  idna : Bool
  fail_on_impact : Bool
}

///|
struct PolicyAuditResult {
  report : String
  scanned_count : Int
  changed_count : Int
}

///|
fn policy_audit_command() -> @argparse.Command {
  @argparse.Command(
    "moonsuffix-policy-audit",
    about="Audit browser-to-strict-ICANN policy migration with a pinned PSL",
    flags=[
      @argparse.FlagArg(
        "idna",
        about="Normalize Unicode inventory hostnames to A-labels",
      ),
      @argparse.FlagArg(
        "fail-on-impact",
        about="Exit nonzero if any inventoried outcome changes or the inventory is empty",
      ),
    ],
    positionals=[
      @argparse.PositionArg(
        "bundle",
        about="Path to a verified PSL snapshot bundle",
        num_args=@argparse.ValueRange::single(),
      ),
      @argparse.PositionArg(
        "hosts",
        about="Path to a hostname inventory with one entry per line",
        num_args=@argparse.ValueRange::single(),
      ),
    ],
  )
}

///|
fn parse_policy_audit_config(
  argv : ArrayView[String],
) -> PolicyAuditConfig raise {
  let matches = policy_audit_command().parse(argv~)
  guard matches.values is { "bundle": [bundle_path], "hosts": [hosts_path], .. } else {
    fail("missing required policy audit input")
  }
  {
    bundle_path,
    hosts_path,
    idna: matches.flags.get("idna").unwrap_or(false),
    fail_on_impact: matches.flags.get("fail-on-impact").unwrap_or(false),
  }
}

///|
fn parse_policy_hosts(
  source : String,
  idna : Bool,
) -> Result[Array[String], String] {
  let hosts : Array[String] = []
  let validator = @moonsuffix.SuffixList::parse("").unwrap()
  let mut line_number = 0
  for line in source.split("\n") {
    line_number = line_number + 1
    let raw_host = line.trim().to_owned()
    if raw_host == "" || raw_host.has_prefix("#") {
      continue
    }
    let host = if idna {
      match @suffix_idna.normalize_hostname(raw_host) {
        Ok(value) => value
        Err(error) =>
          return Err(
            "hostname inventory line \{line_number}: \{error.message()}",
          )
      }
    } else {
      raw_host
    }
    match validator.lookup(host) {
      Ok(_) => ()
      Err(error) =>
        return Err("hostname inventory line \{line_number}: \{error.message()}")
    }
    hosts.push(host)
  }
  Ok(hosts)
}

///|
fn run_policy_audit(
  bundle : String,
  inventory : String,
  idna : Bool,
) -> Result[PolicyAuditResult, String] {
  let snapshot = match @moonsuffix.Snapshot::restore_bundle_text(bundle) {
    Ok(value) => value
    Err(error) => return Err("invalid snapshot: \{error.message()}")
  }
  let hosts = match parse_policy_hosts(inventory, idna) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let list = match @moonsuffix.SuffixList::parse(snapshot.psl_text()) {
    Ok(value) => value
    Err(error) => return Err(error.message())
  }
  let impact = list.analyze_policy_impact(
    hosts,
    @moonsuffix.LookupOptions::browser_default(),
    @moonsuffix.LookupOptions::strict_icann(),
  )
  let output = StringBuilder()
  output.write_string("format=moonsuffix-policy-audit-v1\n")
  for line in snapshot.manifest_text().split("\n") {
    if line.has_prefix("source_revision=") {
      output.write_string(line.to_owned())
      output.write_char('\n')
    }
  }
  output.write_string("psl_sha256=\{snapshot.sha256()}\n")
  output.write_string("rule_count=\{snapshot.rule_count()}\n")
  output.write_string("before_policy=browser\n")
  output.write_string("after_policy=strict-icann\n")
  output.write_string("hosts_scanned=\{impact.scanned_count()}\n")
  output.write_string("hosts_changed=\{impact.changed_count()}\n")
  output.write_string("hosts_unchanged=\{impact.unchanged_count()}\n")
  output.write_string("hostname_impact_csv:\n")
  output.write_string(impact.to_csv())
  Ok({
    report: output.to_string(),
    scanned_count: impact.scanned_count(),
    changed_count: impact.changed_count(),
  })
}

///|
fn policy_audit_gate_error(result : PolicyAuditResult) -> String? {
  if result.scanned_count == 0 {
    Some("policy audit inventory is empty; no hostname was checked")
  } else if result.changed_count > 0 {
    Some(
      "policy migration changes \{result.changed_count} inventoried outcome(s)",
    )
  } else {
    None
  }
}
