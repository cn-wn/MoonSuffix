///|
async fn main {
  let config = parse_bench_config(@env.args()[1:])
  let rules = @fs.read_file(config.rules_path).text()
  let hosts = @fs.read_file(config.hosts_path).text()
  let report = match run_benchmark(rules, hosts, config.idna, 5, 1000) {
    Ok(value) => value
    Err(error) => fail(error)
  }
  @stdio.stdout.write(report)
}
