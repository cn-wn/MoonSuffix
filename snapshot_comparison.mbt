///|
/// A reusable comparison of two pinned PSL snapshots. Both rule sets are
/// compiled once, so hostname and Cookie inventories can share them.
pub struct SnapshotComparison {
  older_ : Snapshot
  newer_ : Snapshot
  before_list_ : SuffixList
  after_list_ : SuffixList
}

///|
/// Compile both snapshots for repeated impact analyses.
///
/// Snapshots can only be created from parsed rules or restored with manifest,
/// canonical-text, digest, and rule-count verification.
pub fn Snapshot::compare_to(
  self : Snapshot,
  newer : Snapshot,
) -> SnapshotComparison {
  {
    older_: self,
    newer_: newer,
    before_list_: SuffixList::parse(self.psl_text_).unwrap(),
    after_list_: SuffixList::parse(newer.psl_text_).unwrap(),
  }
}

///|
/// Compare hostname outcomes without recompiling either rule set.
pub fn SnapshotComparison::analyze_impact(
  self : SnapshotComparison,
  domains : Array[String],
  options : LookupOptions,
) -> SnapshotImpact {
  analyze_impact_with_lists(
    self.older_,
    self.newer_,
    self.before_list_,
    self.after_list_,
    domains,
    options,
  )
}

///|
/// Compare inventoried Cookie Domain decisions without recompiling rules.
pub fn SnapshotComparison::analyze_cookie_scope_impact(
  self : SnapshotComparison,
  inputs : Array[CookieScopeInput],
  options : LookupOptions,
) -> CookieScopeImpactReport {
  analyze_cookie_scope_impact_with_lists(
    self.older_,
    self.newer_,
    self.before_list_,
    self.after_list_,
    inputs,
    options,
  )
}
