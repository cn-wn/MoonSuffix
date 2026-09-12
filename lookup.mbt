///|
fn parse_domain(
  input : String,
) -> Result[(Array[String], Bool, String), DomainError] {
  if input.length() == 0 {
    return Err(EmptyDomain)
  }
  let trailing_dot = input.has_suffix(".")
  let body = if trailing_dot { input[:input.length() - 1] } else { input[:] }
  if body.length() == 0 {
    return Err(EmptyDomain)
  }
  let labels : Array[String] = []
  let mut label_index = 0
  for part in body.split(".") {
    if part.length() == 0 {
      return Err(EmptyLabel(label_index))
    }
    for ch in part {
      if is_rule_whitespace(ch) || ch == '*' || ch == '!' || ch == '/' {
        return Err(InvalidDomainCharacter(label_index, ch))
      }
    }
    labels.push(part.to_lower().to_owned())
    label_index = label_index + 1
  }
  let normalized = labels.join(".") + (if trailing_dot { "." } else { "" })
  Ok((labels, trailing_dot, normalized))
}

///|
fn joined_suffix(
  labels : Array[String],
  count : Int,
  trailing_dot : Bool,
) -> String {
  let text = labels[labels.length() - count:].join(".")
  text + (if trailing_dot { "." } else { "" })
}

///|
fn exact_rule_text(labels : Array[String], depth : Int) -> String {
  labels[labels.length() - depth:].join(".")
}

///|
fn eligible_section(
  sections : Array[RuleSection],
  scope : SectionScope,
) -> RuleSection? {
  for section in sections {
    if section == IcannSection {
      return Some(IcannSection)
    }
  }
  if scope == IcannAndPrivate {
    for section in sections {
      if section == PrivateSection {
        return Some(PrivateSection)
      }
    }
  }
  for section in sections {
    if section == UnsectionedRule {
      return Some(UnsectionedRule)
    }
  }
  None
}

///|
/// Apply the PSL prevailing-rule algorithm to a hostname.
///
/// This method performs case normalization, not IDNA conversion. The hostname
/// and parsed list must already use the same U-label or A-label representation.
pub fn SuffixList::lookup(
  self : SuffixList,
  domain : String,
) -> Result[Lookup, DomainError] {
  self.lookup_with_options(domain, LookupOptions::browser_default())
}

///|
/// Apply the PSL prevailing-rule algorithm with explicit section and
/// unknown-suffix policies.
///
/// Unsectioned rules remain eligible in both scopes so compact and custom rule
/// sets keep their expected behavior. This method performs case normalization,
/// not IDNA conversion.
pub fn SuffixList::lookup_with_options(
  self : SuffixList,
  domain : String,
  options : LookupOptions,
) -> Result[Lookup, DomainError] {
  let (labels, trailing_dot, normalized_domain) = match parse_domain(domain) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let mut node_index = 0
  let mut depth = 0
  let mut best_length = 1
  let mut best_kind = DefaultRule
  let mut best_rule = "*"
  let mut best_section : RuleSection? = None
  let mut exception_length = 0
  let mut exception_rule = ""
  let mut exception_section : RuleSection? = None
  for i = labels.length() - 1; i >= 0; i = i - 1 {
    let next_index = match self.children[node_index].get(labels[i]) {
      Some(index) => index
      None => break
    }
    node_index = next_index
    depth = depth + 1
    match eligible_section(self.exact_sections[node_index], options.scope) {
      Some(section) =>
        if depth >= best_length {
          best_length = depth
          best_kind = ExactRule
          best_rule = exact_rule_text(labels, depth)
          best_section = Some(section)
        }
      None => ()
    }
    match eligible_section(self.wildcard_sections[node_index], options.scope) {
      Some(section) =>
        if i > 0 && depth + 1 > best_length {
          best_length = depth + 1
          best_kind = WildcardRule
          best_rule = "*." + exact_rule_text(labels, depth)
          best_section = Some(section)
        }
      None => ()
    }
    match eligible_section(self.exception_sections[node_index], options.scope) {
      Some(section) =>
        if depth > exception_length {
          exception_length = depth
          exception_rule = "!" + exact_rule_text(labels, depth)
          exception_section = Some(section)
        }
      None => ()
    }
  }
  if best_kind == DefaultRule &&
    exception_length == 0 &&
    options.unknown_suffix == RequireListedSuffix {
    return Err(UnlistedSuffix(normalized_domain))
  }
  let (suffix_length, rule_kind, matched_rule, rule_section) = if exception_length >
    0 {
    (exception_length - 1, ExceptionRule, exception_rule, exception_section)
  } else {
    (best_length, best_kind, best_rule, best_section)
  }
  let public_suffix = joined_suffix(labels, suffix_length, trailing_dot)
  let registrable_domain = if labels.length() > suffix_length {
    Some(joined_suffix(labels, suffix_length + 1, trailing_dot))
  } else {
    None
  }
  Ok({
    normalized_domain,
    public_suffix,
    registrable_domain,
    matched_rule,
    rule_kind,
    rule_section,
  })
}

///|
pub fn SuffixList::public_suffix(
  self : SuffixList,
  domain : String,
) -> Result[String, DomainError] {
  match self.lookup(domain) {
    Ok(result) => Ok(result.public_suffix())
    Err(error) => Err(error)
  }
}

///|
pub fn SuffixList::registrable_domain(
  self : SuffixList,
  domain : String,
) -> Result[String?, DomainError] {
  match self.lookup(domain) {
    Ok(result) => Ok(result.registrable_domain())
    Err(error) => Err(error)
  }
}

///|
pub fn SuffixList::is_public_suffix(
  self : SuffixList,
  domain : String,
) -> Result[Bool, DomainError] {
  match self.lookup(domain) {
    Ok(result) => Ok(result.registrable_domain() is None)
    Err(error) => Err(error)
  }
}
