///|
fn main {
  let rules =
    #|// ===BEGIN ICANN DOMAINS===
    #|com
    #|io
    #|co.uk
    #|*.ck
    #|!www.ck
    #|// ===END ICANN DOMAINS===
    #|// ===BEGIN PRIVATE DOMAINS===
    #|github.io
    #|// ===END PRIVATE DOMAINS===
  let suffixes = @moonsuffix.SuffixList::parse(rules).unwrap()
  println("MoonSuffix compiled \{suffixes.rule_count()} rules")
  for
    domain in [
      "api.shop.example.co.uk", "www.example.com", "a.b.test.ck", "www.www.ck", "service.internal",
    ] {
    match suffixes.lookup(domain) {
      Err(error) => println("\{domain}: \{error.message()}")
      Ok(result) => {
        let registrable = match result.registrable_domain() {
          Some(value) => value
          None => "<none>"
        }
        println(
          "\{domain}: suffix=\{result.public_suffix()} registrable=\{registrable} rule=\{result.matched_rule()}",
        )
      }
    }
  }
  let strict = suffixes
    .lookup_with_options(
      "user.github.io",
      @moonsuffix.LookupOptions::strict_icann(),
    )
    .unwrap()
  let strict_registrable = match strict.registrable_domain() {
    Some(value) => value
    None => "<none>"
  }
  println(
    "strict ICANN user.github.io: suffix=\{strict.public_suffix()} registrable=\{strict_registrable}",
  )
  println("canonical PSL:\n\{suffixes.to_psl_text()}")
  let snapshot = suffixes.snapshot("example-rules-v1")
  println("snapshot manifest:\n\{snapshot.manifest_text()}")
  let updated_rules =
    #|// ===BEGIN ICANN DOMAINS===
    #|com
    #|io
    #|net
    #|co.uk
    #|*.ck
    #|!www.ck
    #|github.io
    #|// ===END ICANN DOMAINS===
  let updated = @moonsuffix.SuffixList::parse(updated_rules)
    .unwrap()
    .snapshot("example-rules-v2")
  println("snapshot diff:\n\{snapshot.diff(updated).report_text()}")
  let audit = suffixes.lookup_batch_with_options(
    ["api.example.com", "service.internal", "a..com"],
    @moonsuffix.LookupOptions::strict_icann(),
  )
  println("batch CSV:\n\{audit.to_csv()}")
}
