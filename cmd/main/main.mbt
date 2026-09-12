///|
fn main {
  let rules =
    #|com
    #|co.uk
    #|*.ck
    #|!www.ck
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
}
