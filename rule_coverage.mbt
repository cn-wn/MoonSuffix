///|
/// One explicit PSL rule membership and its observed selection count.
pub struct RuleCoverageEntry {
  rule_ : String
  section_ : RuleSection
  kind_ : RuleKind
  selected_count_ : Int
}

///|
pub fn RuleCoverageEntry::rule(self : RuleCoverageEntry) -> String {
  self.rule_
}

///|
pub fn RuleCoverageEntry::section(self : RuleCoverageEntry) -> RuleSection {
  self.section_
}

///|
pub fn RuleCoverageEntry::kind(self : RuleCoverageEntry) -> RuleKind {
  self.kind_
}

///|
pub fn RuleCoverageEntry::selected_count(self : RuleCoverageEntry) -> Int {
  self.selected_count_
}

///|
/// Selection frequency of every explicit rule for one hostname inventory.
pub struct RuleCoverageReport {
  entries_ : ReadOnlyArray[RuleCoverageEntry]
  scanned_count_ : Int
  explicit_count_ : Int
  implicit_count_ : Int
  unlisted_count_ : Int
  invalid_count_ : Int
  observed_rule_count_ : Int
}

///|
pub fn RuleCoverageReport::entries(
  self : RuleCoverageReport,
) -> ReadOnlyArray[RuleCoverageEntry] {
  self.entries_
}

///|
pub fn RuleCoverageReport::scanned_count(self : RuleCoverageReport) -> Int {
  self.scanned_count_
}

///|
pub fn RuleCoverageReport::explicit_count(self : RuleCoverageReport) -> Int {
  self.explicit_count_
}

///|
pub fn RuleCoverageReport::implicit_count(self : RuleCoverageReport) -> Int {
  self.implicit_count_
}

///|
pub fn RuleCoverageReport::unlisted_count(self : RuleCoverageReport) -> Int {
  self.unlisted_count_
}

///|
pub fn RuleCoverageReport::invalid_count(self : RuleCoverageReport) -> Int {
  self.invalid_count_
}

///|
pub fn RuleCoverageReport::observed_rule_count(
  self : RuleCoverageReport,
) -> Int {
  self.observed_rule_count_
}

///|
pub fn RuleCoverageReport::unobserved_rule_count(
  self : RuleCoverageReport,
) -> Int {
  self.entries_.length() - self.observed_rule_count_
}

///|
fn coverage_key(rule : String, section : RuleSection) -> String {
  let prefix = match section {
    UnsectionedRule => "u:"
    IcannSection => "i:"
    PrivateSection => "p:"
  }
  prefix + rule
}

///|
fn coverage_kind(rule : String) -> RuleKind {
  if rule.has_prefix("!") {
    ExceptionRule
  } else if rule.has_prefix("*.") {
    WildcardRule
  } else {
    ExactRule
  }
}

///|
fn append_coverage_rules(
  rules : Array[String],
  section : RuleSection,
  keys : Array[(String, RuleSection)],
  counts : Array[Int],
  positions : Map[String, Int],
) -> Unit {
  for rule in rules {
    positions.set(coverage_key(rule, section), keys.length())
    keys.push((rule, section))
    counts.push(0)
  }
}

///|
/// Count which explicit rules prevail for a hostname inventory.
///
/// Each rule-section membership is counted separately. Invalid hostnames and
/// unlisted suffixes are counted but do not interrupt later inputs. A zero
/// count means only that the supplied inventory did not select that rule; it
/// does not prove the rule is unreachable or unnecessary.
pub fn SuffixList::analyze_rule_coverage(
  self : SuffixList,
  domains : Array[String],
  options : LookupOptions,
) -> RuleCoverageReport {
  let (unsectioned, icann, private_rules) = self.sorted_rules_by_section()
  let keys : Array[(String, RuleSection)] = []
  let counts : Array[Int] = []
  let positions : Map[String, Int] = Map([])
  append_coverage_rules(unsectioned, UnsectionedRule, keys, counts, positions)
  append_coverage_rules(icann, IcannSection, keys, counts, positions)
  append_coverage_rules(private_rules, PrivateSection, keys, counts, positions)
  let mut explicit_count = 0
  let mut implicit_count = 0
  let mut unlisted_count = 0
  let mut invalid_count = 0
  for domain in domains {
    match self.lookup_with_options(domain, options) {
      Ok(result) =>
        match result.rule_section() {
          None => implicit_count = implicit_count + 1
          Some(section) => {
            explicit_count = explicit_count + 1
            let index = positions
              .get(coverage_key(result.matched_rule(), section))
              .unwrap()
            counts[index] = counts[index] + 1
          }
        }
      Err(UnlistedSuffix(_)) => unlisted_count = unlisted_count + 1
      Err(_) => invalid_count = invalid_count + 1
    }
  }
  let entries : Array[RuleCoverageEntry] = []
  let mut observed_rule_count = 0
  for index, pair in keys {
    let (rule, section) = pair
    let selected_count = counts[index]
    if selected_count > 0 {
      observed_rule_count = observed_rule_count + 1
    }
    entries.push({
      rule_: rule,
      section_: section,
      kind_: coverage_kind(rule),
      selected_count_: selected_count,
    })
  }
  {
    entries_: ReadOnlyArray::from_array(entries),
    scanned_count_: domains.length(),
    explicit_count_: explicit_count,
    implicit_count_: implicit_count,
    unlisted_count_: unlisted_count,
    invalid_count_: invalid_count,
    observed_rule_count_: observed_rule_count,
  }
}

///|
/// Export every explicit rule membership, including unobserved ones, as CSV.
pub fn RuleCoverageReport::to_csv(self : RuleCoverageReport) -> String {
  let output = StringBuilder()
  output.write_string("\"section\",\"rule\",\"kind\",\"selected_count\"\n")
  for entry in self.entries_ {
    write_csv_row(output, [
      section_name(entry.section_),
      entry.rule_,
      rule_kind_name(entry.kind_),
      entry.selected_count_.to_string(),
    ])
  }
  output.to_string()
}
