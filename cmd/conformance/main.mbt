///|
async fn main {
  let argv = @env.args()
  let config = parse_conformance_config(argv[1:])
  let rules = @fs.read_file(config.rules_path).text()
  let cases = @fs.read_file(config.tests_path).text()
  let result = match run_conformance(rules, cases, config.bundle, config.idna) {
    Ok(value) => value
    Err(error) => fail(error)
  }
  @stdio.stdout.write(result.text)
  if result.failure_count > 0 {
    fail("PSL conformance failed: \{result.failure_count} case(s)")
  }
}
