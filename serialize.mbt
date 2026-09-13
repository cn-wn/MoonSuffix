///|
fn append_rule_to_sections(
  sections : Array[RuleSection],
  rule : String,
  unsectioned : Array[String],
  icann : Array[String],
  private_rules : Array[String],
) -> Unit {
  for section in sections {
    match section {
      UnsectionedRule => unsectioned.push(rule)
      IcannSection => icann.push(rule)
      PrivateSection => private_rules.push(rule)
    }
  }
}

///|
fn SuffixList::collect_serialized_rules(
  self : SuffixList,
  node_index : Int,
  suffix : String,
  unsectioned : Array[String],
  icann : Array[String],
  private_rules : Array[String],
) -> Unit {
  if suffix.length() > 0 {
    append_rule_to_sections(
      self.exact_sections[node_index],
      suffix,
      unsectioned,
      icann,
      private_rules,
    )
    append_rule_to_sections(
      self.wildcard_sections[node_index],
      "*." + suffix,
      unsectioned,
      icann,
      private_rules,
    )
    append_rule_to_sections(
      self.exception_sections[node_index],
      "!" + suffix,
      unsectioned,
      icann,
      private_rules,
    )
  }
  for label, child_index in self.children[node_index] {
    let child_suffix = if suffix.length() == 0 {
      label
    } else {
      label + "." + suffix
    }
    self.collect_serialized_rules(
      child_index, child_suffix, unsectioned, icann, private_rules,
    )
  }
}

///|
fn section_block(name : String, rules : Array[String]) -> String {
  "// ===BEGIN \{name} DOMAINS===\n" +
  rules.join("\n") +
  "\n// ===END \{name} DOMAINS==="
}

///|
fn compare_code_units(left : String, right : String) -> Int {
  let common_length = if left.length() < right.length() {
    left.length()
  } else {
    right.length()
  }
  for i in 0..<common_length {
    let order = left.unsafe_get(i).compare(right.unsafe_get(i))
    if order != 0 {
      return order
    }
  }
  left.length().compare(right.length())
}

///|
fn SuffixList::sorted_rules_by_section(
  self : SuffixList,
) -> (Array[String], Array[String], Array[String]) {
  let unsectioned : Array[String] = []
  let icann : Array[String] = []
  let private_rules : Array[String] = []
  self.collect_serialized_rules(0, "", unsectioned, icann, private_rules)
  unsectioned.sort_by(compare_code_units)
  icann.sort_by(compare_code_units)
  private_rules.sort_by(compare_code_units)
  (unsectioned, icann, private_rules)
}

///|
/// Serialize the compiled rule set to deterministic, parseable PSL text.
///
/// Rules are lowercased and sorted lexicographically within their source
/// section. Comments, blank lines, trailing fields, and original rule order are
/// intentionally not retained. Non-empty output always ends in one newline.
pub fn SuffixList::to_psl_text(self : SuffixList) -> String {
  let (unsectioned, icann, private_rules) = self.sorted_rules_by_section()
  let blocks : Array[String] = []
  if unsectioned.length() > 0 {
    blocks.push(unsectioned.join("\n"))
  }
  if icann.length() > 0 {
    blocks.push(section_block("ICANN", icann))
  }
  if private_rules.length() > 0 {
    blocks.push(section_block("PRIVATE", private_rules))
  }
  if blocks.length() == 0 {
    ""
  } else {
    blocks.join("\n\n") + "\n"
  }
}
