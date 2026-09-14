///|
/// The externally visible effect of a PSL snapshot change on one hostname.
pub(all) enum ImpactKind {
  BecameAccepted
  BecameRejected
  BoundaryChanged
  RuleMetadataChanged
} derive(Eq, Debug)

///|
/// One changed hostname in a snapshot impact analysis.
pub struct DomainImpact {
  index_ : Int
  input_ : String
  kind_ : ImpactKind
  before_ : Result[Lookup, DomainError]
  after_ : Result[Lookup, DomainError]
}

///|
pub fn DomainImpact::index(self : DomainImpact) -> Int {
  self.index_
}

///|
pub fn DomainImpact::input(self : DomainImpact) -> String {
  self.input_
}

///|
pub fn DomainImpact::kind(self : DomainImpact) -> ImpactKind {
  self.kind_
}

///|
pub fn DomainImpact::before(self : DomainImpact) -> Result[Lookup, DomainError] {
  self.before_
}

///|
pub fn DomainImpact::after(self : DomainImpact) -> Result[Lookup, DomainError] {
  self.after_
}

///|
/// Ordered hostname changes caused by replacing one snapshot with another.
pub struct SnapshotImpact {
  from_revision_ : String
  to_revision_ : String
  from_sha256_ : String
  to_sha256_ : String
  scanned_count_ : Int
  unchanged_count_ : Int
  impacts_ : ReadOnlyArray[DomainImpact]
}

///|
pub fn SnapshotImpact::from_revision(self : SnapshotImpact) -> String {
  self.from_revision_
}

///|
pub fn SnapshotImpact::to_revision(self : SnapshotImpact) -> String {
  self.to_revision_
}

///|
pub fn SnapshotImpact::from_sha256(self : SnapshotImpact) -> String {
  self.from_sha256_
}

///|
pub fn SnapshotImpact::to_sha256(self : SnapshotImpact) -> String {
  self.to_sha256_
}

///|
pub fn SnapshotImpact::scanned_count(self : SnapshotImpact) -> Int {
  self.scanned_count_
}

///|
pub fn SnapshotImpact::changed_count(self : SnapshotImpact) -> Int {
  self.impacts_.length()
}

///|
pub fn SnapshotImpact::unchanged_count(self : SnapshotImpact) -> Int {
  self.unchanged_count_
}

///|
pub fn SnapshotImpact::impacts(
  self : SnapshotImpact,
) -> ReadOnlyArray[DomainImpact] {
  self.impacts_
}

///|
pub fn SnapshotImpact::is_empty(self : SnapshotImpact) -> Bool {
  self.impacts_.length() == 0
}

///|
fn classify_impact(
  before : Result[Lookup, DomainError],
  after : Result[Lookup, DomainError],
) -> ImpactKind? {
  match (before, after) {
    (Err(_), Ok(_)) => Some(BecameAccepted)
    (Ok(_), Err(_)) => Some(BecameRejected)
    (Err(_), Err(_)) => None
    (Ok(left), Ok(right)) =>
      if left.public_suffix() != right.public_suffix() ||
        left.registrable_domain() != right.registrable_domain() {
        Some(BoundaryChanged)
      } else if left.matched_rule() != right.matched_rule() ||
        left.rule_kind() != right.rule_kind() ||
        left.rule_section() != right.rule_section() {
        Some(RuleMetadataChanged)
      } else {
        None
      }
  }
}

///|
/// Compare the lookup outcome for every hostname under the same policy.
///
/// Unchanged rows are counted but omitted. Changed rows retain caller order,
/// duplicate inputs, their original index, and both lookup outcomes.
pub fn Snapshot::analyze_impact(
  self : Snapshot,
  newer : Snapshot,
  domains : Array[String],
  options : LookupOptions,
) -> SnapshotImpact {
  let before_list = SuffixList::parse(self.psl_text_).unwrap()
  let after_list = SuffixList::parse(newer.psl_text_).unwrap()
  let impacts : Array[DomainImpact] = []
  let mut unchanged_count = 0
  for index, domain in domains {
    let before = before_list.lookup_with_options(domain, options)
    let after = after_list.lookup_with_options(domain, options)
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
    from_revision_: self.source_revision_,
    to_revision_: newer.source_revision_,
    from_sha256_: self.sha256_,
    to_sha256_: newer.sha256_,
    scanned_count_: domains.length(),
    unchanged_count_: unchanged_count,
    impacts_: ReadOnlyArray::from_array(impacts),
  }
}

///|
fn impact_kind_name(kind : ImpactKind) -> String {
  match kind {
    BecameAccepted => "became_accepted"
    BecameRejected => "became_rejected"
    BoundaryChanged => "boundary_changed"
    RuleMetadataChanged => "rule_metadata_changed"
  }
}

///|
fn append_lookup_fields(
  fields : Array[String],
  outcome : Result[Lookup, DomainError],
) -> Unit {
  match outcome {
    Ok(result) => {
      fields.push("ok")
      fields.push(result.normalized_domain())
      fields.push(result.public_suffix())
      fields.push(result.registrable_domain().unwrap_or(""))
      fields.push(result.matched_rule())
      fields.push(rule_kind_name(result.rule_kind()))
      fields.push(result.rule_section().map(section_name).unwrap_or(""))
      fields.push("")
    }
    Err(error) =>
      for field in ["error", "", "", "", "", "", "", error.message()] {
        fields.push(field)
      }
  }
}

///|
/// Export only changed rows as deterministic, fully quoted CSV.
pub fn SnapshotImpact::to_csv(self : SnapshotImpact) -> String {
  let output = StringBuilder()
  output.write_string(
    "\"index\",\"input\",\"impact\",\"before_status\",\"before_normalized_domain\",\"before_public_suffix\",\"before_registrable_domain\",\"before_matched_rule\",\"before_rule_kind\",\"before_rule_section\",\"before_error\",\"after_status\",\"after_normalized_domain\",\"after_public_suffix\",\"after_registrable_domain\",\"after_matched_rule\",\"after_rule_kind\",\"after_rule_section\",\"after_error\"\n",
  )
  for impact in self.impacts_ {
    let fields = [
      impact.index_.to_string(),
      impact.input_,
      impact_kind_name(impact.kind_),
    ]
    append_lookup_fields(fields, impact.before_)
    append_lookup_fields(fields, impact.after_)
    write_csv_row(output, fields)
  }
  output.to_string()
}
