///|
struct ConformanceConfig {
  rules_path : String
  tests_path : String
  bundle : Bool
}

///|
struct ConformanceResult {
  text : String
  failure_count : Int
}

///|
fn conformance_command() -> @argparse.Command {
  @argparse.Command(
    "moonsuffix-conformance",
    about="Check a local PSL rule set against checkPublicSuffix cases",
    flags=[
      @argparse.FlagArg(
        "bundle",
        about="Verify a versioned snapshot bundle instead of reading raw PSL text",
      ),
    ],
    positionals=[
      @argparse.PositionArg(
        "rules",
        about="Path to PSL text or a snapshot bundle",
        num_args=@argparse.ValueRange::single(),
      ),
      @argparse.PositionArg(
        "tests",
        about="Path to a checkPublicSuffix test file",
        num_args=@argparse.ValueRange::single(),
      ),
    ],
  )
}

///|
fn parse_conformance_config(
  argv : ArrayView[String],
) -> ConformanceConfig raise {
  let matches = conformance_command().parse(argv~)
  guard matches.values is { "rules": [rules_path], "tests": [tests_path], .. } else {
    fail("missing required conformance input")
  }
  {
    rules_path,
    tests_path,
    bundle: matches.flags.get("bundle").unwrap_or(false),
  }
}

///|
fn parse_conformance_snapshot(
  source : String,
  bundle : Bool,
) -> Result[@moonsuffix.Snapshot, String] {
  if bundle {
    match @moonsuffix.Snapshot::restore_bundle_text(source) {
      Ok(value) => Ok(value)
      Err(error) => Err("invalid snapshot: \{error.message()}")
    }
  } else {
    match @moonsuffix.SuffixList::parse(source) {
      Ok(list) => Ok(list.snapshot("raw-input"))
      Err(error) => Err(error.message())
    }
  }
}

///|
fn run_conformance(
  rules : String,
  tests : String,
  bundle : Bool,
) -> Result[ConformanceResult, String] {
  let snapshot = match parse_conformance_snapshot(rules, bundle) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let list = match @moonsuffix.SuffixList::parse(snapshot.psl_text()) {
    Ok(value) => value
    Err(error) => return Err(error.message())
  }
  let result = match list.verify_psl_test_file(tests) {
    Ok(value) => value
    Err(error) => return Err(error.message())
  }
  if result.total_count() == 0 {
    return Err("conformance test file contains no cases")
  }
  let output = StringBuilder()
  output.write_string("format=moonsuffix-conformance-v1\n")
  for line in snapshot.manifest_text().split("\n") {
    if line.has_prefix("source_revision=") {
      output.write_string(line.to_owned())
      output.write_char('\n')
    }
  }
  output.write_string("psl_sha256=\{snapshot.sha256()}\n")
  output.write_string("rule_count=\{snapshot.rule_count()}\n")
  output.write_string("cases=\{result.total_count()}\n")
  output.write_string("passed=\{result.passed_count()}\n")
  output.write_string("failed=\{result.failed_count()}\n")
  output.write_string("failures_csv:\n")
  output.write_string(result.to_csv())
  Ok({ text: output.to_string(), failure_count: result.failed_count(), })
}
