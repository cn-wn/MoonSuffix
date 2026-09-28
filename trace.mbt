///|
/// One rule that matches a hostname's suffix path. A candidate may be
/// excluded by the selected section policy, or lose to a longer rule or an
/// exception. The implicit `*` candidate has no source section.
pub struct RuleCandidate {
  rule_ : String
  kind_ : RuleKind
  section_ : RuleSection?
  eligible_ : Bool
  selected_ : Bool
}

///|
pub fn RuleCandidate::rule(self : RuleCandidate) -> String {
  self.rule_
}

///|
pub fn RuleCandidate::kind(self : RuleCandidate) -> RuleKind {
  self.kind_
}

///|
pub fn RuleCandidate::section(self : RuleCandidate) -> RuleSection? {
  self.section_
}

///|
pub fn RuleCandidate::is_eligible(self : RuleCandidate) -> Bool {
  self.eligible_
}

///|
pub fn RuleCandidate::is_selected(self : RuleCandidate) -> Bool {
  self.selected_
}

///|
/// The rule-selection evidence for one syntactically valid hostname.
/// A strict lookup with no listed suffix has an error outcome, but still
/// exposes the implicit wildcard as an excluded candidate.
pub struct LookupTrace {
  outcome_ : Result[Lookup, DomainError]
  candidates_ : ReadOnlyArray[RuleCandidate]
}

///|
pub fn LookupTrace::outcome(self : LookupTrace) -> Result[Lookup, DomainError] {
  self.outcome_
}

///|
/// Candidates are ordered by suffix depth, then exact, wildcard, exception,
/// and finally by ICANN, PRIVATE, unsectioned membership. The implicit `*`
/// is first. This order does not depend on PSL input order.
pub fn LookupTrace::candidates(
  self : LookupTrace,
) -> ReadOnlyArray[RuleCandidate] {
  self.candidates_
}

///|
fn trace_selected(
  outcome : Result[Lookup, DomainError],
  rule : String,
  kind : RuleKind,
  section : RuleSection?,
) -> Bool {
  match outcome {
    Err(_) => false
    Ok(result) =>
      result.matched_rule() == rule &&
      result.rule_kind() == kind &&
      result.rule_section() == section
  }
}

///|
fn append_trace_candidates(
  candidates : Array[RuleCandidate],
  sections : Array[RuleSection],
  rule : String,
  kind : RuleKind,
  scope : SectionScope,
  outcome : Result[Lookup, DomainError],
) -> Unit {
  for section in [IcannSection, PrivateSection, UnsectionedRule] {
    for present in sections {
      if present == section {
        candidates.push({
          rule_: rule,
          kind_: kind,
          section_: Some(section),
          eligible_: section != PrivateSection || scope == IcannAndPrivate,
          selected_: trace_selected(outcome, rule, kind, Some(section)),
        })
        break
      }
    }
  }
}

///|
/// Explain every matching rule under browser-style lookup policy.
pub fn SuffixList::trace_lookup(
  self : SuffixList,
  domain : String,
) -> Result[LookupTrace, DomainError] {
  self.trace_lookup_with_options(domain, LookupOptions::browser_default())
}

///|
/// Explain the decision made by `lookup_with_options` without changing its
/// fast lookup path. Invalid hostname syntax is returned as an outer error;
/// a valid but unlisted hostname is retained as the trace's error outcome.
pub fn SuffixList::trace_lookup_with_options(
  self : SuffixList,
  domain : String,
  options : LookupOptions,
) -> Result[LookupTrace, DomainError] {
  let labels = match parse_domain(domain) {
    Ok((labels, _, _)) => labels
    Err(error) => return Err(error)
  }
  let outcome = self.lookup_with_options(domain, options)
  let candidates : Array[RuleCandidate] = [
    {
      rule_: "*",
      kind_: DefaultRule,
      section_: None,
      eligible_: options.unknown_suffix == UseDefaultWildcard,
      selected_: trace_selected(outcome, "*", DefaultRule, None),
    },
  ]
  let mut node_index = 0
  let mut depth = 0
  for i = labels.length() - 1; i >= 0; i = i - 1 {
    let next_index = match self.children[node_index].get(labels[i]) {
      Some(index) => index
      None => break
    }
    node_index = next_index
    depth = depth + 1
    let suffix = exact_rule_text(labels, depth)
    append_trace_candidates(
      candidates,
      self.exact_sections[node_index],
      suffix,
      ExactRule,
      options.scope,
      outcome,
    )
    if i > 0 {
      append_trace_candidates(
        candidates,
        self.wildcard_sections[node_index],
        "*." + suffix,
        WildcardRule,
        options.scope,
        outcome,
      )
    }
    append_trace_candidates(
      candidates,
      self.exception_sections[node_index],
      "!" + suffix,
      ExceptionRule,
      options.scope,
      outcome,
    )
  }
  Ok({ outcome_: outcome, candidates_: ReadOnlyArray::from_array(candidates), })
}
