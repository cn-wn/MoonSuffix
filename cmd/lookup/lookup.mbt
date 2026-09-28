///|
struct LookupConfig {
  bundle_path : String
  hostname : String
  idna : Bool
  strict_icann : Bool
}

///|
fn lookup_command() -> @argparse.Command {
  @argparse.Command(
    "moonsuffix-lookup",
    about="Query a hostname against a verified PSL snapshot bundle",
    flags=[
      @argparse.FlagArg(
        "idna",
        about="Normalize the hostname to an A-label with UTS #46",
      ),
      @argparse.FlagArg(
        "strict-icann",
        about="Require a listed ICANN suffix and ignore PRIVATE rules",
      ),
    ],
    positionals=[
      @argparse.PositionArg(
        "bundle",
        about="Path to a versioned PSL snapshot bundle",
        num_args=@argparse.ValueRange::single(),
      ),
      @argparse.PositionArg(
        "hostname",
        about="Hostname to classify; URLs and IP literals are unsupported",
        num_args=@argparse.ValueRange::single(),
      ),
    ],
  )
}

///|
fn parse_lookup_config(argv : ArrayView[String]) -> LookupConfig raise {
  let matches = lookup_command().parse(argv~)
  guard matches.values
    is { "bundle": [bundle_path], "hostname": [hostname], .. } else {
    fail("missing required lookup input")
  }
  {
    bundle_path,
    hostname,
    idna: matches.flags.get("idna").unwrap_or(false),
    strict_icann: matches.flags.get("strict-icann").unwrap_or(false),
  }
}

///|
fn rule_kind_name(kind : @moonsuffix.RuleKind) -> String {
  match kind {
    @moonsuffix.DefaultRule => "default"
    @moonsuffix.ExactRule => "exact"
    @moonsuffix.WildcardRule => "wildcard"
    @moonsuffix.ExceptionRule => "exception"
  }
}

///|
fn section_name(section : @moonsuffix.RuleSection?) -> String {
  match section {
    None => "implicit"
    Some(@moonsuffix.UnsectionedRule) => "unsectioned"
    Some(@moonsuffix.IcannSection) => "ICANN"
    Some(@moonsuffix.PrivateSection) => "PRIVATE"
  }
}

///|
fn query_bundle(
  bundle : String,
  hostname : String,
  idna : Bool,
  strict_icann : Bool,
) -> Result[String, String] {
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
  let result = if idna {
    match @suffix_idna.lookup_with_options(list, hostname, options) {
      Ok(value) => value
      Err(error) => return Err(error.message())
    }
  } else {
    match list.lookup_with_options(hostname, options) {
      Ok(value) => value
      Err(error) => return Err(error.message())
    }
  }
  let output = StringBuilder()
  output.write_string(snapshot.manifest_text())
  output.write_string("normalized_domain=\{result.normalized_domain()}\n")
  output.write_string("public_suffix=\{result.public_suffix()}\n")
  output.write_string(
    "registrable_domain=\{result.registrable_domain().unwrap_or("")}\n",
  )
  output.write_string("matched_rule=\{result.matched_rule()}\n")
  output.write_string("rule_kind=\{rule_kind_name(result.rule_kind())}\n")
  output.write_string("rule_section=\{section_name(result.rule_section())}\n")
  Ok(output.to_string())
}
