///|
fn is_rule_whitespace(ch : Char) -> Bool {
  ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\u{000C}'
}

///|
fn first_rule_field(line : String) -> String {
  let out = StringBuilder()
  for ch in line {
    if is_rule_whitespace(ch) {
      break
    }
    out.write_char(ch)
  }
  out.to_string()
}

///|
fn contains_char(text : StringView, expected : Char) -> Bool {
  for ch in text {
    if ch == expected {
      return true
    }
  }
  false
}

///|
fn parse_rule_labels(
  body : StringView,
  line_number : Int,
  original : String,
) -> Result[Array[String], ListParseError] {
  if body.length() == 0 {
    return Err(InvalidRule(line_number, original, "rule body is empty"))
  }
  let labels : Array[String] = []
  for part in body.split(".") {
    if part.length() == 0 {
      return Err(
        InvalidRule(line_number, original, "rule contains an empty label"),
      )
    }
    if contains_char(part, '*') {
      return Err(
        InvalidRule(
          line_number, original, "wildcard is only allowed as the complete leftmost label",
        ),
      )
    }
    if contains_char(part, '!') {
      return Err(
        InvalidRule(
          line_number, original, "exception marker is only allowed at the start of a rule",
        ),
      )
    }
    if contains_char(part, '/') {
      return Err(
        InvalidRule(line_number, original, "slash is not valid in a rule"),
      )
    }
    labels.push(part.to_lower().to_owned())
  }
  Ok(labels)
}

///|
fn insert_rule(
  children : Array[Map[String, Int]],
  exact : Array[Bool],
  wildcard : Array[Bool],
  exception : Array[Bool],
  labels : Array[String],
  kind : RuleKind,
) -> Bool {
  let mut node_index = 0
  for i = labels.length() - 1; i >= 0; i = i - 1 {
    let label = labels[i]
    let next_index = match children[node_index].get(label) {
      Some(index) => index
      None => {
        let index = children.length()
        children.push(Map([]))
        exact.push(false)
        wildcard.push(false)
        exception.push(false)
        children[node_index].set(label, index)
        index
      }
    }
    node_index = next_index
  }
  match kind {
    ExactRule =>
      if exact[node_index] {
        false
      } else {
        exact[node_index] = true
        true
      }
    WildcardRule =>
      if wildcard[node_index] {
        false
      } else {
        wildcard[node_index] = true
        true
      }
    ExceptionRule =>
      if exception[node_index] {
        false
      } else {
        exception[node_index] = true
        true
      }
    DefaultRule => false
  }
}

///|
/// Parse caller-supplied Public Suffix List text into a reverse-label trie.
///
/// Blank lines and comment lines are ignored. A rule ends at the first
/// whitespace, matching the PSL text format and allowing trailing comments.
pub fn SuffixList::parse(source : String) -> Result[SuffixList, ListParseError] {
  let children : Array[Map[String, Int]] = [Map([])]
  let exact = [false]
  let wildcard = [false]
  let exception = [false]
  let mut rule_count = 0
  let mut line_number = 0
  for raw_line in source.split("\n") {
    line_number = line_number + 1
    let trimmed = raw_line.trim()
    if trimmed.length() == 0 || trimmed.has_prefix("//") {
      continue
    }
    let token = first_rule_field(trimmed.to_owned())
    if token.length() == 0 {
      continue
    }
    let (kind, body) = if token.has_prefix("!") {
      (ExceptionRule, token[1:])
    } else if token.has_prefix("*.") {
      (WildcardRule, token[2:])
    } else {
      (ExactRule, token[:])
    }
    if kind == ExceptionRule && body.find(".") is None {
      return Err(
        InvalidRule(
          line_number, token, "exception rule must contain at least two labels",
        ),
      )
    }
    let labels = match parse_rule_labels(body, line_number, token) {
      Ok(labels) => labels
      Err(error) => return Err(error)
    }
    if insert_rule(children, exact, wildcard, exception, labels, kind) {
      rule_count = rule_count + 1
    }
  }
  Ok({ children, exact, wildcard, exception, rule_count_: rule_count, })
}
