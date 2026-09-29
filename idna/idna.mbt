///|
/// A PSL rule or section structure that cannot be prepared for IDNA lookup.
pub(all) enum IdnaPslError {
  InvalidRuleName(Int, String, String)
  InvalidPsl(@moonsuffix.ListParseError)
}

///|
pub fn IdnaPslError::message(self : IdnaPslError) -> String {
  match self {
    InvalidRuleName(line, rule, reason) =>
      "invalid IDNA rule on line \{line} ('\{rule}'): \{reason}"
    InvalidPsl(error) => error.message()
  }
}

///|
/// A hostname rejected by IDNA or by the selected PSL lookup policy.
pub(all) enum IdnaLookupError {
  InvalidHostname(String, String)
  InvalidDomain(@moonsuffix.DomainError)
}

///|
pub fn IdnaLookupError::message(self : IdnaLookupError) -> String {
  match self {
    InvalidHostname(host, reason) =>
      "invalid IDNA hostname '\{host}': \{reason}"
    InvalidDomain(error) => error.message()
  }
}

///|
fn first_field(line : String) -> String {
  let out = StringBuilder()
  for ch in line {
    if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\u{000C}' {
      break
    }
    out.write_char(ch)
  }
  out.to_string()
}

///|
fn ascii_rule(token : String, line : Int) -> Result[String, IdnaPslError] {
  let (prefix, body) = if token.has_prefix("!") {
    ("!", token[1:].to_owned())
  } else if token.has_prefix("*.") {
    ("*.", token[2:].to_owned())
  } else {
    ("", token)
  }
  Ok(prefix + @unicode_idna.to_ascii(body)) catch {
    error => Err(InvalidRuleName(line, token, error.to_string()))
  }
}

///|
/// Convert a caller-supplied Unicode PSL to A-labels and compile it.
///
/// Section markers retain their meaning; each rule is normalized under the
/// same UTS #46 profile used by `lookup`. The original PSL core stays free of
/// Unicode dependencies.
pub fn parse_psl(
  source : String,
) -> Result[@moonsuffix.SuffixList, IdnaPslError] {
  let output = StringBuilder()
  let mut line_number = 0
  for raw_line in source.split("\n") {
    line_number = line_number + 1
    let line = raw_line.trim().to_owned()
    if line == "" || line.has_prefix("//") {
      output.write_string(line)
    } else {
      let token = first_field(line)
      match ascii_rule(token, line_number) {
        Ok(rule) => output.write_string(rule)
        Err(error) => return Err(error)
      }
    }
    output.write_char('\n')
  }
  match @moonsuffix.SuffixList::parse(output.to_string()) {
    Ok(list) => Ok(list)
    Err(error) => Err(InvalidPsl(error))
  }
}

///|
/// Look up a Unicode or A-label hostname in a list built with `parse_psl`.
pub fn lookup(
  list : @moonsuffix.SuffixList,
  hostname : String,
) -> Result[@moonsuffix.Lookup, IdnaLookupError] {
  lookup_with_options(
    list,
    hostname,
    @moonsuffix.LookupOptions::browser_default(),
  )
}

///|
/// Look up a hostname after UTS #46 conversion using an explicit PSL policy.
pub fn lookup_with_options(
  list : @moonsuffix.SuffixList,
  hostname : String,
  options : @moonsuffix.LookupOptions,
) -> Result[@moonsuffix.Lookup, IdnaLookupError] {
  let ascii = match normalize_hostname(hostname) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match list.lookup_with_options(ascii, options) {
    Ok(result) => Ok(result)
    Err(error) => Err(InvalidDomain(error))
  }
}

///|
/// Convert a DNS hostname to the A-label form used by the IDNA adapter.
pub fn normalize_hostname(hostname : String) -> Result[String, IdnaLookupError] {
  Ok(@unicode_idna.to_ascii(hostname)) catch {
    error => Err(InvalidHostname(hostname, error.to_string()))
  }
}
