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
  exact_sections : Array[Array[RuleSection]],
  wildcard_sections : Array[Array[RuleSection]],
  exception_sections : Array[Array[RuleSection]],
  labels : Array[String],
  kind : RuleKind,
  section : RuleSection,
) -> Bool {
  let mut node_index = 0
  for i = labels.length() - 1; i >= 0; i = i - 1 {
    let label = labels[i]
    let next_index = match children[node_index].get(label) {
      Some(index) => index
      None => {
        let index = children.length()
        children.push(Map([]))
        exact_sections.push([])
        wildcard_sections.push([])
        exception_sections.push([])
        children[node_index].set(label, index)
        index
      }
    }
    node_index = next_index
  }
  let sections = match kind {
    ExactRule => exact_sections[node_index]
    WildcardRule => wildcard_sections[node_index]
    ExceptionRule => exception_sections[node_index]
    DefaultRule => return false
  }
  for existing in sections {
    if existing == section {
      return false
    }
  }
  sections.push(section)
  true
}

///|
fn section_name(section : RuleSection) -> String {
  match section {
    UnsectionedRule => "unsectioned"
    IcannSection => "ICANN"
    PrivateSection => "PRIVATE"
  }
}

///|
/// Parse caller-supplied Public Suffix List text into a reverse-label trie.
///
/// Blank lines and comment lines are ignored. A rule ends at the first
/// whitespace, matching the PSL text format and allowing trailing comments.
pub fn SuffixList::parse(source : String) -> Result[SuffixList, ListParseError] {
  let children : Array[Map[String, Int]] = [Map([])]
  let exact_sections : Array[Array[RuleSection]] = [[]]
  let wildcard_sections : Array[Array[RuleSection]] = [[]]
  let exception_sections : Array[Array[RuleSection]] = [[]]
  let mut rule_count = 0
  let mut line_number = 0
  let mut section = UnsectionedRule
  for raw_line in source.split("\n") {
    line_number = line_number + 1
    let trimmed = raw_line.trim()
    let line = trimmed.to_owned()
    if line == "// ===BEGIN ICANN DOMAINS===" {
      if section != UnsectionedRule {
        return Err(
          InvalidRule(
            line_number,
            line,
            "cannot begin ICANN section inside the \{section_name(section)} section",
          ),
        )
      }
      section = IcannSection
      continue
    }
    if line == "// ===END ICANN DOMAINS===" {
      if section != IcannSection {
        return Err(
          InvalidRule(
            line_number, line, "ICANN end marker has no matching begin marker",
          ),
        )
      }
      section = UnsectionedRule
      continue
    }
    if line == "// ===BEGIN PRIVATE DOMAINS===" {
      if section != UnsectionedRule {
        return Err(
          InvalidRule(
            line_number,
            line,
            "cannot begin PRIVATE section inside the \{section_name(section)} section",
          ),
        )
      }
      section = PrivateSection
      continue
    }
    if line == "// ===END PRIVATE DOMAINS===" {
      if section != PrivateSection {
        return Err(
          InvalidRule(
            line_number, line, "PRIVATE end marker has no matching begin marker",
          ),
        )
      }
      section = UnsectionedRule
      continue
    }
    if trimmed.length() == 0 || trimmed.has_prefix("//") {
      continue
    }
    let token = first_rule_field(line)
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
    if insert_rule(
        children, exact_sections, wildcard_sections, exception_sections, labels,
        kind, section,
      ) {
      rule_count = rule_count + 1
    }
  }
  if section != UnsectionedRule {
    return Err(
      InvalidRule(
        line_number,
        "<end of input>",
        "unterminated \{section_name(section)} section",
      ),
    )
  }
  Ok({
    children,
    exact_sections,
    wildcard_sections,
    exception_sections,
    rule_count_: rule_count,
  })
}
