///|
/// The kind of rule selected by the Public Suffix List algorithm.
pub(all) enum RuleKind {
  DefaultRule
  ExactRule
  WildcardRule
  ExceptionRule
} derive(Eq, Debug)

///|
/// The PSL source section that supplied a prevailing rule.
pub(all) enum RuleSection {
  UnsectionedRule
  IcannSection
  PrivateSection
} derive(Eq, Debug)

///|
/// The PSL sections eligible for a lookup.
pub(all) enum SectionScope {
  IcannAndPrivate
  IcannOnly
} derive(Eq, Debug)

///|
/// The behavior used when no eligible explicit rule matches a hostname.
pub(all) enum UnknownSuffixPolicy {
  UseDefaultWildcard
  RequireListedSuffix
} derive(Eq, Debug)

///|
/// Explicit policy controls for a public-suffix lookup.
pub struct LookupOptions {
  scope : SectionScope
  unknown_suffix : UnknownSuffixPolicy
}

///|
/// Construct lookup options from an eligible-section scope and unknown-suffix
/// policy.
pub fn LookupOptions::new(
  scope : SectionScope,
  unknown_suffix : UnknownSuffixPolicy,
) -> LookupOptions {
  { scope, unknown_suffix, }
}

///|
/// Return browser-style defaults: ICANN and PRIVATE rules plus implicit `*`.
pub fn LookupOptions::browser_default() -> LookupOptions {
  { scope: IcannAndPrivate, unknown_suffix: UseDefaultWildcard, }
}

///|
/// Return a conservative policy that accepts only listed ICANN suffixes.
pub fn LookupOptions::strict_icann() -> LookupOptions {
  { scope: IcannOnly, unknown_suffix: RequireListedSuffix, }
}

///|
pub fn LookupOptions::section_scope(self : LookupOptions) -> SectionScope {
  self.scope
}

///|
pub fn LookupOptions::unknown_suffix_policy(
  self : LookupOptions,
) -> UnknownSuffixPolicy {
  self.unknown_suffix
}

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
  rule_section : RuleSection?
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
/// Return the source section of the prevailing explicit rule. The implicit
/// default wildcard has no source section.
pub fn Lookup::rule_section(self : Lookup) -> RuleSection? {
  self.rule_section
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
  UnlistedSuffix(String)
} derive(Eq, Debug)

///|
pub fn DomainError::message(self : DomainError) -> String {
  match self {
    EmptyDomain => "domain is empty"
    EmptyLabel(index) => "domain contains an empty label at index \{index}"
    InvalidDomainCharacter(index, character) =>
      "domain label \{index} contains invalid character '\{character}'"
    UnlistedSuffix(domain) =>
      "domain '\{domain}' has no suffix listed by the selected policy"
  }
}

///|
/// A compiled, immutable-by-API Public Suffix List rule set.
pub struct SuffixList {
  children : Array[Map[String, Int]]
  exact_sections : Array[Array[RuleSection]]
  wildcard_sections : Array[Array[RuleSection]]
  exception_sections : Array[Array[RuleSection]]
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
