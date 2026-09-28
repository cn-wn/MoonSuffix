///|
/// One Cookie domain-scope decision to re-evaluate across PSL snapshots.
/// Hosts and Domain attributes must already be ASCII/A-label DNS names.
pub struct CookieScopeInput {
  request_host_ : String
  domain_attribute_ : String?
}

///|
pub fn CookieScopeInput::new(
  request_host : String,
  domain_attribute : String?,
) -> CookieScopeInput {
  { request_host_: request_host, domain_attribute_: domain_attribute, }
}

///|
pub fn CookieScopeInput::request_host(self : CookieScopeInput) -> String {
  self.request_host_
}

///|
pub fn CookieScopeInput::domain_attribute(self : CookieScopeInput) -> String? {
  self.domain_attribute_
}

///|
/// Check ASCII DNS syntax without consulting a PSL or applying lookup policy.
/// A syntactically valid Domain attribute may still be rejected later because
/// it is a public suffix or does not domain-match the request host.
pub fn CookieScopeInput::validate_syntax(
  self : CookieScopeInput,
) -> Result[Unit, CookieScopeError] {
  match canonical_request_host(self.request_host_) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match self.domain_attribute_ {
    None => ()
    Some(value) =>
      match canonical_domain_attribute(value) {
        Ok(_) => ()
        Err(error) => return Err(error)
      }
  }
  Ok(())
}

///|
/// A behavioral change in Cookie domain acceptance or stored scope.
pub(all) enum CookieScopeImpactKind {
  CookieBecameAccepted
  CookieBecameRejected
  CookieScopeChanged
}

///|
pub struct CookieScopeImpact {
  index_ : Int
  input_ : CookieScopeInput
  kind_ : CookieScopeImpactKind
  before_ : Result[CookieScope, CookieScopeError]
  after_ : Result[CookieScope, CookieScopeError]
}

///|
pub fn CookieScopeImpact::index(self : CookieScopeImpact) -> Int {
  self.index_
}

///|
pub fn CookieScopeImpact::input(self : CookieScopeImpact) -> CookieScopeInput {
  self.input_
}

///|
pub fn CookieScopeImpact::kind(
  self : CookieScopeImpact,
) -> CookieScopeImpactKind {
  self.kind_
}

///|
pub fn CookieScopeImpact::before(
  self : CookieScopeImpact,
) -> Result[CookieScope, CookieScopeError] {
  self.before_
}

///|
pub fn CookieScopeImpact::after(
  self : CookieScopeImpact,
) -> Result[CookieScope, CookieScopeError] {
  self.after_
}

///|
/// Ordered Cookie-scope changes caused by replacing a pinned PSL snapshot.
pub struct CookieScopeImpactReport {
  from_revision_ : String
  to_revision_ : String
  from_sha256_ : String
  to_sha256_ : String
  scanned_count_ : Int
  unchanged_count_ : Int
  impacts_ : ReadOnlyArray[CookieScopeImpact]
}

///|
pub fn CookieScopeImpactReport::from_revision(
  self : CookieScopeImpactReport,
) -> String {
  self.from_revision_
}

///|
pub fn CookieScopeImpactReport::to_revision(
  self : CookieScopeImpactReport,
) -> String {
  self.to_revision_
}

///|
pub fn CookieScopeImpactReport::from_sha256(
  self : CookieScopeImpactReport,
) -> String {
  self.from_sha256_
}

///|
pub fn CookieScopeImpactReport::to_sha256(
  self : CookieScopeImpactReport,
) -> String {
  self.to_sha256_
}

///|
pub fn CookieScopeImpactReport::scanned_count(
  self : CookieScopeImpactReport,
) -> Int {
  self.scanned_count_
}

///|
pub fn CookieScopeImpactReport::changed_count(
  self : CookieScopeImpactReport,
) -> Int {
  self.impacts_.length()
}

///|
pub fn CookieScopeImpactReport::unchanged_count(
  self : CookieScopeImpactReport,
) -> Int {
  self.unchanged_count_
}

///|
pub fn CookieScopeImpactReport::impacts(
  self : CookieScopeImpactReport,
) -> ReadOnlyArray[CookieScopeImpact] {
  self.impacts_
}

///|
pub fn CookieScopeImpactReport::is_empty(
  self : CookieScopeImpactReport,
) -> Bool {
  self.impacts_.length() == 0
}

///|
fn classify_cookie_scope_impact(
  before : Result[CookieScope, CookieScopeError],
  after : Result[CookieScope, CookieScopeError],
) -> CookieScopeImpactKind? {
  match (before, after) {
    (Err(_), Ok(_)) => Some(CookieBecameAccepted)
    (Ok(_), Err(_)) => Some(CookieBecameRejected)
    (Err(_), Err(_)) => None
    (Ok(old_scope), Ok(new_scope)) =>
      if old_scope != new_scope {
        Some(CookieScopeChanged)
      } else {
        None
      }
  }
}

///|
/// Re-evaluate an ordered inventory of Cookie Domain decisions under two
/// verified snapshots using the same lookup policy.
///
/// Changes to Cookie acceptance or the stored domain/host-only flag are
/// reported. Two rejections count as unchanged even if their error text differs.
/// Invalid inputs are retained as row-level outcomes and do not stop the scan.
pub fn Snapshot::analyze_cookie_scope_impact(
  self : Snapshot,
  newer : Snapshot,
  inputs : Array[CookieScopeInput],
  options : LookupOptions,
) -> CookieScopeImpactReport {
  let before_list = SuffixList::parse(self.psl_text_).unwrap()
  let after_list = SuffixList::parse(newer.psl_text_).unwrap()
  let impacts : Array[CookieScopeImpact] = []
  let mut unchanged_count = 0
  for index, input in inputs {
    let before = before_list.resolve_cookie_scope_with_options(
      input.request_host_,
      input.domain_attribute_,
      options,
    )
    let after = after_list.resolve_cookie_scope_with_options(
      input.request_host_,
      input.domain_attribute_,
      options,
    )
    match classify_cookie_scope_impact(before, after) {
      Some(kind) =>
        impacts.push({
          index_: index,
          input_: input,
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
    scanned_count_: inputs.length(),
    unchanged_count_: unchanged_count,
    impacts_: ReadOnlyArray::from_array(impacts),
  }
}

///|
fn cookie_scope_impact_kind_name(kind : CookieScopeImpactKind) -> String {
  match kind {
    CookieBecameAccepted => "became_accepted"
    CookieBecameRejected => "became_rejected"
    CookieScopeChanged => "scope_changed"
  }
}

///|
fn append_cookie_scope_fields(
  fields : Array[String],
  outcome : Result[CookieScope, CookieScopeError],
) -> Unit {
  match outcome {
    Ok(scope) => {
      fields.push("ok")
      fields.push(scope.domain())
      fields.push(scope.is_host_only().to_string())
      fields.push("")
    }
    Err(error) => {
      fields.push("error")
      fields.push("")
      fields.push("")
      fields.push(error.message())
    }
  }
}

///|
/// Export changed rows to deterministic, fully quoted CSV. A separate
/// presence field distinguishes a missing Domain attribute from an empty one.
pub fn CookieScopeImpactReport::to_csv(
  self : CookieScopeImpactReport,
) -> String {
  let output = StringBuilder()
  output.write_string(
    "\"index\",\"request_host\",\"domain_attribute_present\",\"domain_attribute\",\"impact\",\"before_status\",\"before_domain\",\"before_host_only\",\"before_error\",\"after_status\",\"after_domain\",\"after_host_only\",\"after_error\"\n",
  )
  for impact in self.impacts_ {
    let attribute = impact.input_.domain_attribute_
    let fields = [
      impact.index_.to_string(),
      impact.input_.request_host_,
      (attribute is Some(_)).to_string(),
      attribute.unwrap_or(""),
      cookie_scope_impact_kind_name(impact.kind_),
    ]
    append_cookie_scope_fields(fields, impact.before_)
    append_cookie_scope_fields(fields, impact.after_)
    write_csv_row(output, fields)
  }
  output.to_string()
}
