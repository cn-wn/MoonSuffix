///|
/// A domain that cannot identify a registrable site.
pub(all) enum SiteError {
  InvalidSiteDomain(DomainError)
  NoRegistrableDomain(String)
  InvalidSiteScheme(String)
  InvalidSiteHost(String, String)
} derive(Eq, Debug)

///|
pub fn SiteError::message(self : SiteError) -> String {
  match self {
    InvalidSiteDomain(error) => error.message()
    NoRegistrableDomain(domain) =>
      "domain '\{domain}' is a public suffix and has no registrable site"
    InvalidSiteScheme(scheme) =>
      "unsupported site scheme '\{scheme}': expected http or https"
    InvalidSiteHost(host, reason) =>
      "invalid site hostname '\{host}': \{reason}"
  }
}

///|
/// The scheme and registrable domain of a DNS-backed web site.
///
/// Ports and paths do not affect the site identity. The hostname must already
/// be in ASCII/A-label form; use the IDNA adapter before constructing a site
/// from a Unicode hostname.
pub struct SchemefulSite {
  scheme_ : String
  registrable_domain_ : String
}

///|
pub fn SchemefulSite::scheme(self : SchemefulSite) -> String {
  self.scheme_
}

///|
pub fn SchemefulSite::registrable_domain(self : SchemefulSite) -> String {
  self.registrable_domain_
}

///|
pub fn SchemefulSite::key(self : SchemefulSite) -> String {
  self.scheme_ + "://" + self.registrable_domain_
}

///|
pub fn SchemefulSite::same_site(
  self : SchemefulSite,
  other : SchemefulSite,
) -> Bool {
  self.scheme_ == other.scheme_ &&
  self.registrable_domain_ == other.registrable_domain_
}

///|
/// Construct a DNS-backed web site using browser-style PSL semantics.
pub fn SuffixList::schemeful_site(
  self : SuffixList,
  scheme : String,
  hostname : String,
) -> Result[SchemefulSite, SiteError] {
  self.schemeful_site_with_options(
    scheme,
    hostname,
    LookupOptions::browser_default(),
  )
}

///|
/// Construct a web site under an explicit PSL section and fallback policy.
/// Scheme is case-insensitive; only HTTP and HTTPS DNS hosts are supported.
pub fn SuffixList::schemeful_site_with_options(
  self : SuffixList,
  scheme : String,
  hostname : String,
  options : LookupOptions,
) -> Result[SchemefulSite, SiteError] {
  let normalized_scheme = scheme.to_lower()
  if normalized_scheme != "http" && normalized_scheme != "https" {
    return Err(InvalidSiteScheme(scheme))
  }
  let host = remove_trailing_root_dot(hostname)
  let ascii_host = match canonical_ascii_dns_name(host) {
    Ok(value) => value
    Err(reason) => return Err(InvalidSiteHost(hostname, reason))
  }
  match self.site_key_with_options(ascii_host, options) {
    Ok(domain) =>
      Ok({ scheme_: normalized_scheme, registrable_domain_: domain, })
    Err(error) => Err(error)
  }
}

///|
fn remove_trailing_root_dot(domain : String) -> String {
  if domain.has_suffix(".") {
    domain[:domain.length() - 1].to_owned()
  } else {
    domain
  }
}

///|
/// Return the canonical registrable site key using browser-style PSL policy.
///
/// The key is the registrable domain without a trailing DNS root dot. A public
/// suffix by itself cannot identify an independently controlled site.
pub fn SuffixList::site_key(
  self : SuffixList,
  domain : String,
) -> Result[String, SiteError] {
  self.site_key_with_options(domain, LookupOptions::browser_default())
}

///|
/// Return the canonical registrable site key under an explicit lookup policy.
pub fn SuffixList::site_key_with_options(
  self : SuffixList,
  domain : String,
  options : LookupOptions,
) -> Result[String, SiteError] {
  match self.lookup_with_options(domain, options) {
    Err(error) => Err(InvalidSiteDomain(error))
    Ok(result) =>
      match result.registrable_domain() {
        Some(site) => Ok(remove_trailing_root_dot(site))
        None => Err(NoRegistrableDomain(result.normalized_domain()))
      }
  }
}

///|
/// Test whether two hostnames have the same registrable site key using the
/// browser-style PSL policy.
///
/// This compares hostname boundaries only. Schemeful same-site callers must
/// additionally compare their already-parsed URL schemes.
pub fn SuffixList::same_registrable_site(
  self : SuffixList,
  left : String,
  right : String,
) -> Result[Bool, SiteError] {
  self.same_registrable_site_with_options(
    left,
    right,
    LookupOptions::browser_default(),
  )
}

///|
/// Test whether two hostnames have the same registrable site key under an
/// explicit lookup policy. The left hostname is validated first.
pub fn SuffixList::same_registrable_site_with_options(
  self : SuffixList,
  left : String,
  right : String,
  options : LookupOptions,
) -> Result[Bool, SiteError] {
  let left_site = match self.site_key_with_options(left, options) {
    Ok(site) => site
    Err(error) => return Err(error)
  }
  let right_site = match self.site_key_with_options(right, options) {
    Ok(site) => site
    Err(error) => return Err(error)
  }
  Ok(left_site == right_site)
}
