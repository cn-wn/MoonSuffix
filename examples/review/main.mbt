///|
fn review_report() -> String {
  let before_rules =
    #|// ===BEGIN ICANN DOMAINS===
    #|app
    #|co.uk
    #|// ===END ICANN DOMAINS===
  let after_rules =
    #|// ===BEGIN ICANN DOMAINS===
    #|app
    #|co.uk
    #|// ===END ICANN DOMAINS===
    #|// ===BEGIN PRIVATE DOMAINS===
    #|glideos.app
    #|// ===END PRIVATE DOMAINS===
  let before = @moonsuffix.SuffixList::parse(before_rules).unwrap()
  let after = @moonsuffix.SuffixList::parse(after_rules).unwrap()
  let ordinary = before.lookup("api.shop.example.co.uk").unwrap()
  let old_snapshot = before.snapshot("before-private-rule")
  let new_snapshot = after.snapshot("after-private-rule")
  let host_impact = old_snapshot.analyze_impact(
    new_snapshot,
    ["api.glideos.app"],
    @moonsuffix.LookupOptions::browser_default(),
  )
  let cookie_impact = old_snapshot.analyze_cookie_scope_impact(
    new_snapshot,
    [@moonsuffix.CookieScopeInput::new("api.glideos.app", Some(".glideos.app"))],
    @moonsuffix.LookupOptions::browser_default(),
  )
  let changed_host = host_impact.impacts()[0]
  let old_host = changed_host.before().unwrap()
  let new_host = changed_host.after().unwrap()
  let changed_cookie = cookie_impact.impacts()[0]
  let old_cookie = changed_cookie.before().unwrap()
  let cookie_after = match changed_cookie.after() {
    Ok(_) => "accepted"
    Err(error) => error.message()
  }
  "lookup api.shop.example.co.uk: suffix=\{ordinary.public_suffix()}, registrable=\{ordinary.registrable_domain().unwrap()}\n" +
  "PSL update: +PRIVATE glideos.app\n" +
  "api.glideos.app: registrable \{old_host.registrable_domain().unwrap()} -> \{new_host.registrable_domain().unwrap()}\n" +
  "Cookie Domain=.glideos.app: \{old_cookie.domain()} accepted -> \{cookie_after}\n" +
  "changed hosts=\{host_impact.changed_count()}, changed Cookie scopes=\{cookie_impact.changed_count()}"
}

///|
fn main {
  println(review_report())
}
