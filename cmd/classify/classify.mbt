///|
struct ClassifyConfig {
  bundle_path : String
  hosts_path : String
  strict_icann : Bool
  fail_on_error : Bool
}

///|
struct ClassifyResult {
  report : String
  scanned_count : Int
  error_count : Int
}

///|
fn classify_command() -> @argparse.Command {
  @argparse.Command(
    "moonsuffix-classify",
    about="Classify a hostname inventory against a verified PSL snapshot",
    flags=[
      @argparse.FlagArg(
        "strict-icann",
        about="Require listed ICANN suffixes and ignore PRIVATE rules",
      ),
      @argparse.FlagArg(
        "fail-on-error",
        about="Exit nonzero if a row fails or the inventory is empty",
      ),
    ],
    positionals=[
      @argparse.PositionArg(
        "bundle",
        about="Path to a versioned PSL snapshot bundle",
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
fn parse_classify_config(argv : ArrayView[String]) -> ClassifyConfig raise {
  let matches = classify_command().parse(argv~)
  guard matches.values is { "bundle": [bundle_path], "hosts": [hosts_path], .. } else {
    fail("missing required classification input")
  }
  {
    bundle_path,
    hosts_path,
    strict_icann: matches.flags.get("strict-icann").unwrap_or(false),
    fail_on_error: matches.flags.get("fail-on-error").unwrap_or(false),
  }
}

///|
fn parse_classify_hosts(source : String) -> Array[String] {
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
fn run_classification(
  bundle : String,
  inventory : String,
  strict_icann : Bool,
) -> Result[ClassifyResult, String] {
  let snapshot = match @moonsuffix.Snapshot::restore_bundle_text(bundle) {
    Ok(value) => value
    Err(error) => return Err("invalid snapshot: \{error.message()}")
  }
  let list = match @moonsuffix.SuffixList::parse(snapshot.psl_text()) {
    Ok(value) => value
    Err(error) => return Err(error.message())
  }
  let options = if strict_icann {
    @moonsuffix.LookupOptions::strict_icann()
  } else {
    @moonsuffix.LookupOptions::browser_default()
  }
  let policy = if strict_icann { "strict-icann" } else { "browser" }
  let hosts = parse_classify_hosts(inventory)
  let batch = list.lookup_batch_with_options(hosts, options)
  let output = StringBuilder()
  output.write_string("format=moonsuffix-classify-v1\n")
  for line in snapshot.manifest_text().split("\n") {
    if line.has_prefix("source_revision=") {
      output.write_string(line.to_owned())
      output.write_char('\n')
    }
  }
  output.write_string("psl_sha256=\{snapshot.sha256()}\n")
  output.write_string("rule_count=\{snapshot.rule_count()}\n")
  output.write_string("policy=\{policy}\n")
  output.write_string("hosts_scanned=\{batch.length()}\n")
  output.write_string("hosts_succeeded=\{batch.success_count()}\n")
  output.write_string("hosts_failed=\{batch.error_count()}\n")
  output.write_string("hostname_csv:\n")
  output.write_string(batch.to_csv())
  Ok({
    report: output.to_string(),
    scanned_count: batch.length(),
    error_count: batch.error_count(),
  })
}

///|
fn classification_gate_error(result : ClassifyResult) -> String? {
  if result.scanned_count == 0 {
    Some("classification inventory is empty; no hostname was checked")
  } else if result.error_count > 0 {
    Some("classification failed for \{result.error_count} hostname(s)")
  } else {
    None
  }
}
