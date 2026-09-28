///|
fn main {
  let list = @suffix_idna.parse_psl("公司.cn\ncom\n").unwrap()
  let result = @suffix_idna.lookup(list, "商店.公司.cn").unwrap()
  println("public suffix: \{result.public_suffix()}")
  println(
    "registrable domain: \{result.registrable_domain().unwrap_or("<none>")}",
  )
}
