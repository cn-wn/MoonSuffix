///|
struct AuditConfig {
  old_psl_path : String
  new_psl_path : String
  hosts_path : String
  from_revision : String
  to_revision : String
  strict_icann : Bool
}

///|
fn audit_command() -> @argparse.Command {
  @argparse.Command(
    "moonsuffix-audit",
    about="Compare two PSL files and report hostname boundary changes",
    flags=[
      @argparse.FlagArg(
        "strict-icann",
        about="Require listed ICANN suffixes and ignore PRIVATE rules",
      ),
    ],
    options=[
      @argparse.OptionArg(
        "from-revision",
        long="from",
        about="Opaque revision label for the old PSL",
        required=true,
      ),
      @argparse.OptionArg(
        "to-revision",
        long="to",
        about="Opaque revision label for the candidate PSL",
        required=true,
      ),
    ],
    positionals=[
      @argparse.PositionArg(
        "old-psl",
        about="Path to the currently deployed PSL file",
        num_args=@argparse.ValueRange::single(),
      ),
      @argparse.PositionArg(
        "new-psl",
        about="Path to the candidate PSL file",
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
fn parse_audit_config(argv : ArrayView[String]) -> AuditConfig raise {
  let matches = audit_command().parse(argv~)
  guard matches.values
    is {
      "old-psl": [old_psl_path],
      "new-psl": [new_psl_path],
      "hosts": [hosts_path],
      "from-revision": [from_revision],
      "to-revision": [to_revision],
      ..
    } else {
    fail("missing required audit input")
  }
  {
    old_psl_path,
    new_psl_path,
    hosts_path,
    from_revision,
    to_revision,
    strict_icann: matches.flags.get("strict-icann").unwrap_or(false),
  }
}

///|
fn parse_host_inventory(source : String) -> Array[String] {
  let hosts : Array[String] = []
  for line in source.split("\n") {
    let host = line.trim().to_owned()
    if host != "" && !host.has_prefix("#") {
      hosts.push(host)
    }
  }
  hosts
}

///|
fn parse_psl_for_audit(
  label : String,
  source : String,
) -> Result[@moonsuffix.SuffixList, String] {
  match @moonsuffix.SuffixList::parse(source) {
    Ok(suffixes) => Ok(suffixes)
    Err(error) => Err("\{label} PSL: \{error.message()}")
  }
}

///|
fn build_audit_report(
  old_psl : String,
  new_psl : String,
  host_inventory : String,
  from_revision : String,
  to_revision : String,
  strict_icann : Bool,
) -> Result[String, String] {
  let old_suffixes = match parse_psl_for_audit("old", old_psl) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let new_suffixes = match parse_psl_for_audit("candidate", new_psl) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let hosts = parse_host_inventory(host_inventory)
  let old_snapshot = old_suffixes.snapshot(from_revision)
  let new_snapshot = new_suffixes.snapshot(to_revision)
  let options = if strict_icann {
    @moonsuffix.LookupOptions::strict_icann()
  } else {
    @moonsuffix.LookupOptions::browser_default()
  }
  let policy_name = if strict_icann { "strict-icann" } else { "browser" }
  let diff = old_snapshot.diff(new_snapshot)
  let impact = old_snapshot.analyze_impact(new_snapshot, hosts, options)
  let output = StringBuilder()
  output.write_string("format=moonsuffix-audit-v1\n")
  output.write_string("policy=\{policy_name}\n")
  output.write_string("old_rules=\{old_snapshot.rule_count()}\n")
  output.write_string("new_rules=\{new_snapshot.rule_count()}\n")
  output.write_string("hosts_scanned=\{impact.scanned_count()}\n")
  output.write_string("hosts_changed=\{impact.changed_count()}\n")
  output.write_string("hosts_unchanged=\{impact.unchanged_count()}\n")
  output.write_string("rule_diff:\n")
  output.write_string(diff.report_text())
  output.write_string("hostname_impact_csv:\n")
  output.write_string(impact.to_csv())
  Ok(output.to_string())
}
