///|
/// The hostname scope a user agent would store for a cookie.
pub struct CookieScope {
  domain_ : String
  host_only_ : Bool
} derive(Eq, Debug)

///|
/// Return the canonical ASCII domain stored with the cookie.
pub fn CookieScope::domain(self : CookieScope) -> String {
  self.domain_
}

///|
/// Return whether the cookie is restricted to exactly the request host.
pub fn CookieScope::is_host_only(self : CookieScope) -> Bool {
  self.host_only_
}

///|
/// Test only the domain component of Cookie delivery to a request host.
///
/// A host-only cookie matches exactly one canonical DNS hostname. A Domain
/// cookie also matches descendants at a label boundary. The caller must
/// separately enforce path, Secure, expiration, and other Cookie attributes.
pub fn CookieScope::matches_host(
  self : CookieScope,
  request_host : String,
) -> Result[Bool, CookieScopeError] {
  let host = match canonical_request_host(request_host) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok(
    host == self.domain_ ||
    (!self.host_only_ && host.has_suffix("." + self.domain_)),
  )
}

///|
/// A request host or Domain attribute that cannot produce a safe cookie scope.
pub(all) enum CookieScopeError {
  InvalidRequestHost(String, String)
  InvalidDomainAttribute(String, String)
  PublicSuffixDomain(String)
  DomainMismatch(String, String)
} derive(Eq, Debug)

///|
pub fn CookieScopeError::message(self : CookieScopeError) -> String {
  match self {
    InvalidRequestHost(host, reason) =>
      "invalid cookie request host '\{host}': \{reason}"
    InvalidDomainAttribute(domain, reason) =>
      "invalid cookie Domain attribute '\{domain}': \{reason}"
    PublicSuffixDomain(domain) =>
      "cookie Domain attribute '\{domain}' is a public suffix"
    DomainMismatch(host, domain) =>
      "request host '\{host}' does not domain-match cookie Domain '\{domain}'"
  }
}

///|
fn canonical_ascii_dns_name(input : String) -> Result[String, String] {
  if input.length() == 0 {
    return Err("domain is empty")
  }
  if input.length() > 253 {
    return Err("domain exceeds 253 ASCII characters")
  }
  let mut label_index = 0
  for label in input.split(".") {
    if label.length() == 0 {
      return Err("domain contains an empty label at index \{label_index}")
    }
    if label.length() > 63 {
      return Err("domain label \{label_index} exceeds 63 ASCII characters")
    }
    if label.has_prefix("-") || label.has_suffix("-") {
      return Err("domain label \{label_index} starts or ends with '-'")
    }
    for character in label {
      if !character.is_ascii() {
        return Err(
          "domain label \{label_index} contains non-ASCII character '\{character}'",
        )
      }
      if !character.is_ascii_alphabetic() &&
        !character.is_ascii_digit() &&
        character != '-' {
        return Err(
          "domain label \{label_index} contains invalid character '\{character}'",
        )
      }
    }
    label_index = label_index + 1
  }
  Ok(input.to_lower())
}

///|
fn canonical_request_host(input : String) -> Result[String, CookieScopeError] {
  let without_root = remove_trailing_root_dot(input)
  match canonical_ascii_dns_name(without_root) {
    Ok(host) => Ok(host)
    Err(reason) => Err(InvalidRequestHost(input, reason))
  }
}

///|
fn canonical_domain_attribute(
  input : String,
) -> Result[String, CookieScopeError] {
  let without_leading_dot = if input.has_prefix(".") {
    input[1:].to_owned()
  } else {
    input
  }
  if without_leading_dot.has_suffix(".") {
    return Err(
      InvalidDomainAttribute(input, "a trailing root dot is not permitted"),
    )
  }
  match canonical_ascii_dns_name(without_leading_dot) {
    Ok(domain) => Ok(domain)
    Err(reason) => Err(InvalidDomainAttribute(input, reason))
  }
}

///|
/// Resolve an optional Cookie Domain attribute using browser-style PSL policy.
///
/// The inputs must be already extracted DNS hostnames. A missing Domain
/// attribute produces a host-only scope. A present attribute may have one
/// compatibility leading dot and must be an ASCII DNS name.
pub fn SuffixList::resolve_cookie_scope(
  self : SuffixList,
  request_host : String,
  domain_attribute : String?,
) -> Result[CookieScope, CookieScopeError] {
  self.resolve_cookie_scope_with_options(
    request_host,
    domain_attribute,
    LookupOptions::browser_default(),
  )
}

///|
/// Resolve a Cookie Domain attribute under an explicit PSL lookup policy.
pub fn SuffixList::resolve_cookie_scope_with_options(
  self : SuffixList,
  request_host : String,
  domain_attribute : String?,
  options : LookupOptions,
) -> Result[CookieScope, CookieScopeError] {
  let host = match canonical_request_host(request_host) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match self.lookup_with_options(host, options) {
    Ok(_) => ()
    Err(error) => return Err(InvalidRequestHost(request_host, error.message()))
  }
  let attribute = match domain_attribute {
    None => return Ok({ domain_: host, host_only_: true, })
    Some(value) => value
  }
  let domain = match canonical_domain_attribute(attribute) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let domain_lookup = match self.lookup_with_options(domain, options) {
    Ok(value) => value
    Err(error) => return Err(InvalidDomainAttribute(attribute, error.message()))
  }
  if domain_lookup.registrable_domain() is None {
    if domain == host {
      return Ok({ domain_: host, host_only_: true, })
    }
    return Err(PublicSuffixDomain(domain))
  }
  if host != domain && !host.has_suffix("." + domain) {
    return Err(DomainMismatch(host, domain))
  }
  Ok({ domain_: domain, host_only_: false, })
}

///|
/// Enumerate valid, shareable Cookie Domain scopes from narrowest to broadest.
///
/// The request host is included when it is not itself a public suffix. The
/// public suffix is never included. A public-suffix request host therefore
/// yields no shareable scope, even though an equal Domain attribute resolves
/// to a host-only cookie for compatibility.
pub fn SuffixList::shareable_cookie_scopes(
  self : SuffixList,
  request_host : String,
) -> Result[ReadOnlyArray[CookieScope], CookieScopeError] {
  self.shareable_cookie_scopes_with_options(
    request_host,
    LookupOptions::browser_default(),
  )
}

///|
/// Enumerate shareable Cookie Domain scopes under an explicit PSL policy.
pub fn SuffixList::shareable_cookie_scopes_with_options(
  self : SuffixList,
  request_host : String,
  options : LookupOptions,
) -> Result[ReadOnlyArray[CookieScope], CookieScopeError] {
  let host = match canonical_request_host(request_host) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let lookup = match self.lookup_with_options(host, options) {
    Ok(value) => value
    Err(error) => return Err(InvalidRequestHost(request_host, error.message()))
  }
  let registrable = match lookup.registrable_domain() {
    Some(value) => value
    None => return Ok(ReadOnlyArray::from_array([]))
  }
  let labels : Array[String] = []
  for label in host.split(".") {
    labels.push(label.to_owned())
  }
  let mut registrable_label_count = 0
  for _ in registrable.split(".") {
    registrable_label_count = registrable_label_count + 1
  }
  let scopes : Array[CookieScope] = []
  for start = 0
      start <= labels.length() - registrable_label_count
      start = start + 1 {
    scopes.push({ domain_: labels[start:].join("."), host_only_: false, })
  }
  Ok(ReadOnlyArray::from_array(scopes))
}
