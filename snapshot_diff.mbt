///|
/// A semantic change between two canonical PSL snapshots.
pub(all) enum SnapshotChange {
  AddedRule(String, RuleSection)
  RemovedRule(String, RuleSection)
  MovedRule(String, RuleSection, RuleSection)
} derive(Eq, Debug)

///|
/// A deterministic semantic comparison between two snapshots.
pub struct SnapshotDiff {
  from_revision_ : String
  to_revision_ : String
  from_sha256_ : String
  to_sha256_ : String
  changes_ : ReadOnlyArray[SnapshotChange]
  added_count_ : Int
  removed_count_ : Int
  moved_count_ : Int
}

///|
fn section_bit(section : RuleSection) -> UInt {
  match section {
    UnsectionedRule => 1U
    IcannSection => 2U
    PrivateSection => 4U
  }
}

///|
fn add_rules_to_mask(
  masks : Map[String, UInt],
  rules : Array[String],
  section : RuleSection,
) -> Unit {
  let bit = section_bit(section)
  for rule in rules {
    let previous = masks.get(rule).unwrap_or(0U)
    masks.set(rule, previous | bit)
  }
}

///|
fn SuffixList::rule_section_masks(self : SuffixList) -> Map[String, UInt] {
  let masks : Map[String, UInt] = Map([])
  let (unsectioned, icann, private_rules) = self.sorted_rules_by_section()
  add_rules_to_mask(masks, unsectioned, UnsectionedRule)
  add_rules_to_mask(masks, icann, IcannSection)
  add_rules_to_mask(masks, private_rules, PrivateSection)
  masks
}

///|
fn sections_in_mask(mask : UInt) -> Array[RuleSection] {
  let sections : Array[RuleSection] = []
  for section in [UnsectionedRule, IcannSection, PrivateSection] {
    if (mask & section_bit(section)) != 0U {
      sections.push(section)
    }
  }
  sections
}

///|
/// Compare this snapshot with a newer snapshot.
///
/// A rule is classified as moved only when exactly one old section disappears
/// and exactly one new section appears. Ambiguous multi-section changes remain
/// explicit additions and removals.
pub fn Snapshot::diff(self : Snapshot, newer : Snapshot) -> SnapshotDiff {
  let before = SuffixList::parse(self.psl_text_).unwrap()
  let after = SuffixList::parse(newer.psl_text_).unwrap()
  let before_masks = before.rule_section_masks()
  let after_masks = after.rule_section_masks()
  let all_rules : Map[String, Bool] = Map([])
  for rule, _ in before_masks {
    all_rules.set(rule, true)
  }
  for rule, _ in after_masks {
    all_rules.set(rule, true)
  }
  let rules : Array[String] = []
  for rule, _ in all_rules {
    rules.push(rule)
  }
  rules.sort_by(compare_code_units)
  let changes : Array[SnapshotChange] = []
  let mut added_count = 0
  let mut removed_count = 0
  let mut moved_count = 0
  for rule in rules {
    let before_mask = before_masks.get(rule).unwrap_or(0U)
    let after_mask = after_masks.get(rule).unwrap_or(0U)
    let removed = sections_in_mask(before_mask & after_mask.lnot())
    let added = sections_in_mask(after_mask & before_mask.lnot())
    if removed.length() == 1 && added.length() == 1 {
      changes.push(MovedRule(rule, removed[0], added[0]))
      moved_count = moved_count + 1
    } else {
      for section in removed {
        changes.push(RemovedRule(rule, section))
        removed_count = removed_count + 1
      }
      for section in added {
        changes.push(AddedRule(rule, section))
        added_count = added_count + 1
      }
    }
  }
  {
    from_revision_: self.source_revision_,
    to_revision_: newer.source_revision_,
    from_sha256_: self.sha256_,
    to_sha256_: newer.sha256_,
    changes_: ReadOnlyArray::from_array(changes),
    added_count_: added_count,
    removed_count_: removed_count,
    moved_count_: moved_count,
  }
}

///|
pub fn SnapshotDiff::from_revision(self : SnapshotDiff) -> String {
  self.from_revision_
}

///|
pub fn SnapshotDiff::to_revision(self : SnapshotDiff) -> String {
  self.to_revision_
}

///|
pub fn SnapshotDiff::from_sha256(self : SnapshotDiff) -> String {
  self.from_sha256_
}

///|
pub fn SnapshotDiff::to_sha256(self : SnapshotDiff) -> String {
  self.to_sha256_
}

///|
pub fn SnapshotDiff::changes(
  self : SnapshotDiff,
) -> ReadOnlyArray[SnapshotChange] {
  self.changes_
}

///|
pub fn SnapshotDiff::added_count(self : SnapshotDiff) -> Int {
  self.added_count_
}

///|
pub fn SnapshotDiff::removed_count(self : SnapshotDiff) -> Int {
  self.removed_count_
}

///|
pub fn SnapshotDiff::moved_count(self : SnapshotDiff) -> Int {
  self.moved_count_
}

///|
pub fn SnapshotDiff::is_empty(self : SnapshotDiff) -> Bool {
  self.changes_.length() == 0
}

///|
fn write_change_line(output : StringBuilder, change : SnapshotChange) -> Unit {
  match change {
    AddedRule(rule, section) =>
      output.write_string("+ [\{section_name(section)}] \{rule}\n")
    RemovedRule(rule, section) =>
      output.write_string("- [\{section_name(section)}] \{rule}\n")
    MovedRule(rule, from, to) =>
      output.write_string(
        "> [\{section_name(from)}->\{section_name(to)}] \{rule}\n",
      )
  }
}

///|
/// Return a deterministic, line-oriented semantic change report.
pub fn SnapshotDiff::report_text(self : SnapshotDiff) -> String {
  let output = StringBuilder()
  output.write_string("format=moonsuffix-diff-v1\n")
  output.write_string("from_revision=\{manifest_escape(self.from_revision_)}\n")
  output.write_string("to_revision=\{manifest_escape(self.to_revision_)}\n")
  output.write_string("from_sha256=\{self.from_sha256_}\n")
  output.write_string("to_sha256=\{self.to_sha256_}\n")
  output.write_string("added=\{self.added_count_}\n")
  output.write_string("removed=\{self.removed_count_}\n")
  output.write_string("moved=\{self.moved_count_}\n")
  output.write_string("changes:\n")
  for change in self.changes_ {
    write_change_line(output, change)
  }
  output.to_string()
}
