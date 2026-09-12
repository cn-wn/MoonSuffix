///|
/// The kind of rule selected by the Public Suffix List algorithm.
pub(all) enum RuleKind {
  DefaultRule
  ExactRule
  WildcardRule
  ExceptionRule
} derive(Eq, Debug)

///|
/// An explainable public-suffix lookup result.
///
/// `normalized_domain` is case-normalized only. Callers are responsible for
/// applying the same IDNA profile to the list and hostname before lookup.
pub struct Lookup {
  normalized_domain : String
  public_suffix : String
  registrable_domain : String?
  matched_rule : String
  rule_kind : RuleKind
}

///|
/// Return the case-normalized input domain, preserving one trailing root dot.
pub fn Lookup::normalized_domain(self : Lookup) -> String {
  self.normalized_domain
}

///|
/// Return the public suffix selected by the prevailing rule.
pub fn Lookup::public_suffix(self : Lookup) -> String {
  self.public_suffix
}

///|
/// Return the public suffix plus one label, if that label exists.
pub fn Lookup::registrable_domain(self : Lookup) -> String? {
  self.registrable_domain
}

///|
/// Return the prevailing PSL rule, including `*.` or `!` when applicable.
pub fn Lookup::matched_rule(self : Lookup) -> String {
  self.matched_rule
}

///|
/// Return the kind of the prevailing rule.
pub fn Lookup::rule_kind(self : Lookup) -> RuleKind {
  self.rule_kind
}

///|
/// A malformed rule in caller-supplied PSL text.
pub(all) enum ListParseError {
  InvalidRule(Int, String, String)
} derive(Eq, Debug)

///|
pub fn ListParseError::message(self : ListParseError) -> String {
  match self {
    InvalidRule(line, rule, reason) =>
      "invalid PSL rule on line \{line} ('\{rule}'): \{reason}"
  }
}

///|
/// A hostname that cannot be split into valid lookup labels.
pub(all) enum DomainError {
  EmptyDomain
  EmptyLabel(Int)
  InvalidDomainCharacter(Int, Char)
} derive(Eq, Debug)

///|
pub fn DomainError::message(self : DomainError) -> String {
  match self {
    EmptyDomain => "domain is empty"
    EmptyLabel(index) => "domain contains an empty label at index \{index}"
    InvalidDomainCharacter(index, character) =>
      "domain label \{index} contains invalid character '\{character}'"
  }
}

///|
/// A compiled, immutable-by-API Public Suffix List rule set.
pub struct SuffixList {
  children : Array[Map[String, Int]]
  exact : Array[Bool]
  wildcard : Array[Bool]
  exception : Array[Bool]
  rule_count_ : Int
}

///|
/// Return the number of distinct rules compiled into this list.
pub fn SuffixList::rule_count(self : SuffixList) -> Int {
  self.rule_count_
}

///|
/// Return the number of trie nodes used by this compiled list.
pub fn SuffixList::node_count(self : SuffixList) -> Int {
  self.children.length()
}
