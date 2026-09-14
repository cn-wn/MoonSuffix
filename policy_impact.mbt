///|
/// Ordered hostname changes caused by switching lookup policies.
pub struct PolicyImpactReport {
  before_options_ : LookupOptions
  after_options_ : LookupOptions
  scanned_count_ : Int
  unchanged_count_ : Int
  impacts_ : ReadOnlyArray[DomainImpact]
}

///|
pub fn PolicyImpactReport::before_options(
  self : PolicyImpactReport,
) -> LookupOptions {
  self.before_options_
}

///|
pub fn PolicyImpactReport::after_options(
  self : PolicyImpactReport,
) -> LookupOptions {
  self.after_options_
}

///|
pub fn PolicyImpactReport::scanned_count(self : PolicyImpactReport) -> Int {
  self.scanned_count_
}

///|
pub fn PolicyImpactReport::changed_count(self : PolicyImpactReport) -> Int {
  self.impacts_.length()
}

///|
pub fn PolicyImpactReport::unchanged_count(self : PolicyImpactReport) -> Int {
  self.unchanged_count_
}

///|
pub fn PolicyImpactReport::impacts(
  self : PolicyImpactReport,
) -> ReadOnlyArray[DomainImpact] {
  self.impacts_
}

///|
pub fn PolicyImpactReport::is_empty(self : PolicyImpactReport) -> Bool {
  self.impacts_.length() == 0
}

///|
/// Compare each hostname under two lookup policies against the same rule set.
///
/// Unchanged rows are counted but omitted. Changed rows preserve caller order,
/// duplicates, their original index, and both lookup outcomes.
pub fn SuffixList::analyze_policy_impact(
  self : SuffixList,
  domains : Array[String],
  before_options : LookupOptions,
  after_options : LookupOptions,
) -> PolicyImpactReport {
  let impacts : Array[DomainImpact] = []
  let mut unchanged_count = 0
  for index, domain in domains {
    let before = self.lookup_with_options(domain, before_options)
    let after = self.lookup_with_options(domain, after_options)
    match classify_impact(before, after) {
      Some(kind) =>
        impacts.push({
          index_: index,
          input_: domain,
          kind_: kind,
          before_: before,
          after_: after,
        })
      None => unchanged_count = unchanged_count + 1
    }
  }
  {
    before_options_: before_options,
    after_options_: after_options,
    scanned_count_: domains.length(),
    unchanged_count_: unchanged_count,
    impacts_: ReadOnlyArray::from_array(impacts),
  }
}

///|
/// Export only policy-sensitive rows as deterministic, fully quoted CSV.
pub fn PolicyImpactReport::to_csv(self : PolicyImpactReport) -> String {
  domain_impacts_to_csv(self.impacts_)
}
