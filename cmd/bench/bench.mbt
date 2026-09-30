///|
struct BenchConfig {
  rules_path : String
  hosts_path : String
  idna : Bool
}

///|
fn bench_command() -> @argparse.Command {
  @argparse.Command(
    "moonsuffix-bench",
    about="Measure PSL compilation and lookups against local input files",
    flags=[
      @argparse.FlagArg(
        "idna",
        about="Normalize Unicode PSL rules and inventory hostnames to A-labels",
      ),
    ],
    positionals=[
      @argparse.PositionArg(
        "rules",
        about="Path to a local PSL text file",
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
fn parse_bench_config(argv : ArrayView[String]) -> BenchConfig raise {
  let matches = bench_command().parse(argv~)
  guard matches.values is { "rules": [rules_path], "hosts": [hosts_path], .. } else {
    fail("missing required benchmark input")
  }
  { rules_path, hosts_path, idna: matches.flags.get("idna").unwrap_or(false), }
}

///|
fn compile_rules(
  source : String,
  idna : Bool,
) -> Result[@moonsuffix.SuffixList, String] {
  if idna {
    match @suffix_idna.parse_psl(source) {
      Ok(list) => Ok(list)
      Err(error) => Err(error.message())
    }
  } else {
    match @moonsuffix.SuffixList::parse(source) {
      Ok(list) => Ok(list)
      Err(error) => Err(error.message())
    }
  }
}

///|
fn prepare_bench_hosts(
  list : @moonsuffix.SuffixList,
  inventory : String,
  idna : Bool,
) -> Result[Array[String], String] {
  let hosts : Array[String] = []
  let mut line_number = 0
  for raw_line in inventory.split("\n") {
    line_number = line_number + 1
    let host = raw_line.trim().to_owned()
    if host == "" || host.has_prefix("#") {
      continue
    }
    let normalized = if idna {
      match @suffix_idna.normalize_hostname(host) {
        Ok(value) => value
        Err(error) =>
          return Err("inventory line \{line_number}: \{error.message()}")
      }
    } else {
      host
    }
    match list.lookup(normalized) {
      Ok(_) => hosts.push(normalized)
      Err(error) =>
        return Err("inventory line \{line_number}: \{error.message()}")
    }
  }
  if hosts.is_empty() {
    return Err("benchmark inventory is empty")
  }
  Ok(hosts)
}

///|
/// Benchmark report uses microseconds from MoonBit's monotonic clock. Input
/// loading, inventory normalization, and validation are outside the timed
/// regions. Parsing includes IDNA conversion when requested; lookup uses
/// already-normalized A-label hostnames.
fn run_benchmark(
  source : String,
  inventory : String,
  idna : Bool,
  parse_rounds : Int,
  lookup_rounds : Int,
) -> Result[String, String] {
  if parse_rounds <= 0 || lookup_rounds <= 0 {
    return Err("benchmark round counts must be positive")
  }
  let list = match compile_rules(source, idna) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let hosts = match prepare_bench_hosts(list, inventory, idna) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let snapshot = list.snapshot("benchmark-input")
  let mut parse_total_us = 0.0
  let mut parse_checksum = 0
  for _ in 0..<parse_rounds {
    let started = @clock.monotonic_clock_start()
    let compiled = compile_rules(source, idna)
    parse_total_us = parse_total_us + @clock.monotonic_clock_end(started)
    match compiled {
      Ok(value) => parse_checksum = parse_checksum + value.rule_count()
      Err(error) => return Err(error)
    }
  }
  let mut lookup_total_us = 0.0
  let mut lookup_checksum = 0
  for _ in 0..<lookup_rounds {
    let started = @clock.monotonic_clock_start()
    for host in hosts {
      match list.lookup(host) {
        Ok(value) =>
          lookup_checksum = lookup_checksum + value.public_suffix().length()
        Err(error) => return Err(error.message())
      }
    }
    lookup_total_us = lookup_total_us + @clock.monotonic_clock_end(started)
  }
  let output = StringBuilder()
  output.write_string("format=moonsuffix-benchmark-v1\n")
  output.write_string("psl_sha256=\{snapshot.sha256()}\n")
  output.write_string("rule_count=\{snapshot.rule_count()}\n")
  output.write_string("host_count=\{hosts.length()}\n")
  output.write_string("idna=\{idna}\n")
  output.write_string("parse_rounds=\{parse_rounds}\n")
  output.write_string("parse_total_us=\{parse_total_us}\n")
  output.write_string(
    "parse_mean_us=\{parse_total_us / parse_rounds.to_double()}\n",
  )
  output.write_string("parse_checksum=\{parse_checksum}\n")
  output.write_string("lookup_rounds=\{lookup_rounds}\n")
  output.write_string("lookup_total_us=\{lookup_total_us}\n")
  output.write_string(
    "lookup_mean_us_per_host=\{lookup_total_us / (lookup_rounds * hosts.length()).to_double()}\n",
  )
  output.write_string("lookup_checksum=\{lookup_checksum}\n")
  Ok(output.to_string())
}
