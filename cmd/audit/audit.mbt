///|
struct AuditConfig {
  old_psl_path : String
  new_psl_path : String
  hosts_path : String
  cookie_inventory_path : String?
  from_revision : String?
  to_revision : String?
  strict_icann : Bool
  fail_on_impact : Bool
  bundles : Bool
}

///|
struct AuditResult {
  report : String
  changed_count : Int
}

///|
fn audit_command() -> @argparse.Command {
  @argparse.Command(
    "moonsuffix-audit",
    about="Compare two PSL files and report hostname and Cookie-scope changes",
    flags=[
      @argparse.FlagArg(
        "strict-icann",
        about="Require listed ICANN suffixes and ignore PRIVATE rules",
      ),
      @argparse.FlagArg(
        "fail-on-impact",
        about="Exit nonzero when an inventoried hostname or Cookie scope changes",
      ),
      @argparse.FlagArg(
        "bundles",
        about="Read and verify versioned snapshot bundles instead of raw PSL files",
      ),
    ],
    options=[
      @argparse.OptionArg(
        "from-revision",
        long="from",
        about="Opaque revision label for the old PSL",
      ),
      @argparse.OptionArg(
        "to-revision",
        long="to",
        about="Opaque revision label for the candidate PSL",
      ),
      @argparse.OptionArg(
        "cookie-inventory",
        long="cookie-inventory",
        about="Optional tab-separated Cookie host and Domain inventory",
      ),
    ],
    positionals=[
      @argparse.PositionArg(
        "old-psl",
        about="Path to the deployed PSL or snapshot bundle",
        num_args=@argparse.ValueRange::single(),
      ),
      @argparse.PositionArg(
        "new-psl",
        about="Path to the candidate PSL or snapshot bundle",
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
      ..
    } else {
    fail("missing required audit input")
  }
  let from_revision = match matches.values {
    { "from-revision": [value], .. } => Some(value)
    _ => None
  }
  let to_revision = match matches.values {
    { "to-revision": [value], .. } => Some(value)
    _ => None
  }
  let cookie_inventory_path = match matches.values {
    { "cookie-inventory": [value], .. } => Some(value)
    _ => None
  }
  let bundles = matches.flags.get("bundles").unwrap_or(false)
  if bundles {
    if from_revision is Some(_) || to_revision is Some(_) {
      fail("--from and --to are stored in bundles and must be omitted")
    }
  } else if from_revision is None || to_revision is None {
    fail("raw PSL inputs require --from and --to revision labels")
  }
  {
    old_psl_path,
    new_psl_path,
    hosts_path,
    cookie_inventory_path,
    from_revision,
    to_revision,
    strict_icann: matches.flags.get("strict-icann").unwrap_or(false),
    fail_on_impact: matches.flags.get("fail-on-impact").unwrap_or(false),
    bundles,
  }
}

///|
fn parse_host_inventory(source : String) -> Result[Array[String], String] {
  let hosts : Array[String] = []
  let validator = @moonsuffix.SuffixList::parse("").unwrap()
  let mut line_number = 0
  for line in source.split("\n") {
    line_number = line_number + 1
    let host = line.trim().to_owned()
    if host != "" && !host.has_prefix("#") {
      match validator.lookup(host) {
        Ok(_) => ()
        Err(error) =>
          return Err(
            "hostname inventory line \{line_number}: \{error.message()}",
          )
      }
      hosts.push(host)
    }
  }
  Ok(hosts)
}

///|
/// Each non-comment line is a request host, optionally followed by one tab
/// and a Cookie Domain attribute. One field means the attribute is absent;
/// malformed hostnames and Domain values fail with their source line.
fn parse_cookie_inventory(
  source : String,
) -> Result[Array[@moonsuffix.CookieScopeInput], String] {
  let inputs : Array[@moonsuffix.CookieScopeInput] = []
  let mut line_number = 0
  for raw_line in source.split("\n") {
    line_number = line_number + 1
    let line = if raw_line.has_suffix("\r") {
      raw_line[:raw_line.length() - 1].to_owned()
    } else {
      raw_line.to_owned()
    }
    let trimmed = line.trim()
    if trimmed.length() == 0 || trimmed.has_prefix("#") {
      continue
    }
    let fields : Array[String] = []
    for field in line.split("\t") {
      fields.push(field.to_owned())
    }
    if fields.length() > 2 {
      return Err(
        "cookie inventory line \{line_number}: expected a host and at most one Domain field",
      )
    }
    let attribute = if fields.length() == 2 { Some(fields[1]) } else { None }
    let input = @moonsuffix.CookieScopeInput::new(fields[0], attribute)
    match input.validate_syntax() {
      Ok(_) => ()
      Err(error) =>
        return Err("cookie inventory line \{line_number}: \{error.message()}")
    }
    inputs.push(input)
  }
  Ok(inputs)
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
  cookie_inventory : String?,
  from_revision : String,
  to_revision : String,
  strict_icann : Bool,
) -> Result[AuditResult, String] {
  let old_suffixes = match parse_psl_for_audit("old", old_psl) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let new_suffixes = match parse_psl_for_audit("candidate", new_psl) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let old_snapshot = old_suffixes.snapshot(from_revision)
  let new_snapshot = new_suffixes.snapshot(to_revision)
  render_audit_report(
    old_snapshot, new_snapshot, host_inventory, cookie_inventory, strict_icann,
  )
}

///|
fn parse_bundle_for_audit(
  label : String,
  source : String,
) -> Result[@moonsuffix.Snapshot, String] {
  match @moonsuffix.Snapshot::restore_bundle_text(source) {
    Ok(snapshot) => Ok(snapshot)
    Err(error) => Err("\{label} snapshot: \{error.message()}")
  }
}

///|
fn build_bundle_audit_report(
  old_bundle : String,
  new_bundle : String,
  host_inventory : String,
  cookie_inventory : String?,
  strict_icann : Bool,
) -> Result[AuditResult, String] {
  let old_snapshot = match parse_bundle_for_audit("old", old_bundle) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let new_snapshot = match parse_bundle_for_audit("candidate", new_bundle) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  render_audit_report(
    old_snapshot, new_snapshot, host_inventory, cookie_inventory, strict_icann,
  )
}

///|
fn render_audit_report(
  old_snapshot : @moonsuffix.Snapshot,
  new_snapshot : @moonsuffix.Snapshot,
  host_inventory : String,
  cookie_inventory : String?,
  strict_icann : Bool,
) -> Result[AuditResult, String] {
  let hosts = match parse_host_inventory(host_inventory) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
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
  let mut cookie_changed_count = 0
  match cookie_inventory {
    None => ()
    Some(source) => {
      let inputs = match parse_cookie_inventory(source) {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      let cookie_impact = old_snapshot.analyze_cookie_scope_impact(
        new_snapshot, inputs, options,
      )
      cookie_changed_count = cookie_impact.changed_count()
      output.write_string("cookies_scanned=\{cookie_impact.scanned_count()}\n")
      output.write_string("cookies_changed=\{cookie_changed_count}\n")
      output.write_string(
        "cookies_unchanged=\{cookie_impact.unchanged_count()}\n",
      )
      output.write_string("cookie_scope_impact_csv:\n")
      output.write_string(cookie_impact.to_csv())
    }
  }
  Ok({
    report: output.to_string(),
    changed_count: impact.changed_count() + cookie_changed_count,
  })
}
