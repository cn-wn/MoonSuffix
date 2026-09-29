///|
fn main {
  let list = @suffix_idna.parse_psl("公司.cn\ncom\n").unwrap()
  let result = @suffix_idna.lookup(list, "商店.公司.cn").unwrap()
  println("public suffix: \{result.public_suffix()}")
  println(
    "registrable domain: \{result.registrable_domain().unwrap_or("<none>")}",
  )
  let cookie = @suffix_idna.resolve_cookie_scope(
    list,
    "api.商店.公司.cn",
    Some(".商店.公司.cn"),
  ).unwrap()
  println("cookie Domain: \{cookie.domain()}")
  println(
    "shareable Cookie scopes: \{@suffix_idna.shareable_cookie_scopes(list, "api.商店.公司.cn").unwrap().length()}",
  )
}
