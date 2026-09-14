///|
/// A domain that cannot identify a registrable site.
pub(all) enum SiteError {
  InvalidSiteDomain(DomainError)
  NoRegistrableDomain(String)
} derive(Eq, Debug)

///|
pub fn SiteError::message(self : SiteError) -> String {
  match self {
    InvalidSiteDomain(error) => error.message()
    NoRegistrableDomain(domain) =>
      "domain '\{domain}' is a public suffix and has no registrable site"
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
