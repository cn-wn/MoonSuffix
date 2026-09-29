///|
fn cookie_ascii_host(
  request_host : String,
) -> Result[String, @moonsuffix.CookieScopeError] {
  Ok(@unicode_idna.to_ascii(request_host)) catch {
    error =>
      Err(@moonsuffix.InvalidRequestHost(request_host, error.to_string()))
  }
}

///|
fn cookie_ascii_attribute(
  attribute : String,
) -> Result[String, @moonsuffix.CookieScopeError] {
  if attribute.has_suffix(".") {
    return Err(
      @moonsuffix.InvalidDomainAttribute(
        attribute, "a trailing root dot is not permitted",
      ),
    )
  }
  let dotted = attribute.has_prefix(".")
  let body = if dotted { attribute[1:].to_owned() } else { attribute }
  let ascii = @unicode_idna.to_ascii(body) catch {
    error =>
      return Err(
        @moonsuffix.InvalidDomainAttribute(attribute, error.to_string()),
      )
  }
  Ok(if dotted { "." + ascii } else { ascii })
}

///|
fn original_cookie_error(
  error : @moonsuffix.CookieScopeError,
  request_host : String,
  domain_attribute : String?,
) -> @moonsuffix.CookieScopeError {
  match error {
    @moonsuffix.InvalidRequestHost(_, reason) =>
      @moonsuffix.InvalidRequestHost(request_host, reason)
    @moonsuffix.InvalidDomainAttribute(_, reason) =>
      @moonsuffix.InvalidDomainAttribute(domain_attribute.unwrap_or(""), reason)
    other => other
  }
}

///|
/// Resolve a Unicode Cookie request host and optional Domain attribute.
///
/// Both names use the same UTS #46 profile as IDNA hostname lookup. The
/// resulting scope contains a canonical ASCII/A-label stored domain.
pub fn resolve_cookie_scope(
  list : @moonsuffix.SuffixList,
  request_host : String,
  domain_attribute : String?,
) -> Result[@moonsuffix.CookieScope, @moonsuffix.CookieScopeError] {
  resolve_cookie_scope_with_options(
    list,
    request_host,
    domain_attribute,
    @moonsuffix.LookupOptions::browser_default(),
  )
}

///|
/// Resolve a Unicode Cookie Domain under an explicit PSL lookup policy.
pub fn resolve_cookie_scope_with_options(
  list : @moonsuffix.SuffixList,
  request_host : String,
  domain_attribute : String?,
  options : @moonsuffix.LookupOptions,
) -> Result[@moonsuffix.CookieScope, @moonsuffix.CookieScopeError] {
  let host = match cookie_ascii_host(request_host) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let attribute = match domain_attribute {
    None => None
    Some(raw) =>
      match cookie_ascii_attribute(raw) {
        Ok(value) => Some(value)
        Err(error) => return Err(error)
      }
  }
  match list.resolve_cookie_scope_with_options(host, attribute, options) {
    Ok(scope) => Ok(scope)
    Err(error) =>
      Err(original_cookie_error(error, request_host, domain_attribute))
  }
}

///|
/// Enumerate shareable Cookie Domain scopes for a Unicode request host.
pub fn shareable_cookie_scopes(
  list : @moonsuffix.SuffixList,
  request_host : String,
) -> Result[
  ReadOnlyArray[@moonsuffix.CookieScope],
  @moonsuffix.CookieScopeError,
] {
  shareable_cookie_scopes_with_options(
    list,
    request_host,
    @moonsuffix.LookupOptions::browser_default(),
  )
}

///|
/// Enumerate Unicode Cookie Domain scopes under an explicit PSL policy.
pub fn shareable_cookie_scopes_with_options(
  list : @moonsuffix.SuffixList,
  request_host : String,
  options : @moonsuffix.LookupOptions,
) -> Result[
  ReadOnlyArray[@moonsuffix.CookieScope],
  @moonsuffix.CookieScopeError,
] {
  let host = match cookie_ascii_host(request_host) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match list.shareable_cookie_scopes_with_options(host, options) {
    Ok(scopes) => Ok(scopes)
    Err(error) => Err(original_cookie_error(error, request_host, None))
  }
}

///|
/// Check the domain component of Cookie delivery to a Unicode hostname.
pub fn cookie_scope_matches_host(
  scope : @moonsuffix.CookieScope,
  request_host : String,
) -> Result[Bool, @moonsuffix.CookieScopeError] {
  let host = match cookie_ascii_host(request_host) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match scope.matches_host(host) {
    Ok(matches) => Ok(matches)
    Err(error) => Err(original_cookie_error(error, request_host, None))
  }
}
