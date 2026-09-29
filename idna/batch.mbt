///|
/// One Unicode input and its IDNA-aware PSL lookup outcome.
pub struct IdnaBatchItem {
  index_ : Int
  input_ : String
  result_ : Result[@moonsuffix.Lookup, IdnaLookupError]
}

///|
pub fn IdnaBatchItem::index(self : IdnaBatchItem) -> Int {
  self.index_
}

///|
pub fn IdnaBatchItem::input(self : IdnaBatchItem) -> String {
  self.input_
}

///|
pub fn IdnaBatchItem::result(
  self : IdnaBatchItem,
) -> Result[@moonsuffix.Lookup, IdnaLookupError] {
  self.result_
}

///|
/// Ordered results from a batch IDNA lookup, including row-level failures.
pub struct IdnaBatchReport {
  items_ : ReadOnlyArray[IdnaBatchItem]
  success_count_ : Int
  error_count_ : Int
}

///|
pub fn IdnaBatchReport::items(
  self : IdnaBatchReport,
) -> ReadOnlyArray[IdnaBatchItem] {
  self.items_
}

///|
pub fn IdnaBatchReport::length(self : IdnaBatchReport) -> Int {
  self.items_.length()
}

///|
pub fn IdnaBatchReport::success_count(self : IdnaBatchReport) -> Int {
  self.success_count_
}

///|
pub fn IdnaBatchReport::error_count(self : IdnaBatchReport) -> Int {
  self.error_count_
}

///|
/// Classify Unicode or A-label hostnames without stopping on an invalid row.
pub fn lookup_batch(
  list : @moonsuffix.SuffixList,
  domains : Array[String],
) -> IdnaBatchReport {
  lookup_batch_with_options(
    list,
    domains,
    @moonsuffix.LookupOptions::browser_default(),
  )
}

///|
/// Classify hostnames under an explicit PSL policy after UTS #46 conversion.
pub fn lookup_batch_with_options(
  list : @moonsuffix.SuffixList,
  domains : Array[String],
  options : @moonsuffix.LookupOptions,
) -> IdnaBatchReport {
  let items : Array[IdnaBatchItem] = []
  let mut success_count = 0
  let mut error_count = 0
  for index, domain in domains {
    let result = lookup_with_options(list, domain, options)
    match result {
      Ok(_) => success_count = success_count + 1
      Err(_) => error_count = error_count + 1
    }
    items.push({ index_: index, input_: domain, result_: result, })
  }
  {
    items_: ReadOnlyArray::from_array(items),
    success_count_: success_count,
    error_count_: error_count,
  }
}

///|
fn idna_csv_field(value : String) -> String {
  let output = StringBuilder()
  output.write_char('"')
  for character in value {
    if character == '"' {
      output.write_string("\"\"")
    } else {
      output.write_char(character)
    }
  }
  output.write_char('"')
  output.to_string()
}

///|
fn idna_csv_row(output : StringBuilder, fields : Array[String]) -> Unit {
  for index, field in fields {
    if index > 0 {
      output.write_char(',')
    }
    output.write_string(idna_csv_field(field))
  }
  output.write_char('\n')
}

///|
fn idna_rule_kind_name(kind : @moonsuffix.RuleKind) -> String {
  match kind {
    @moonsuffix.DefaultRule => "default"
    @moonsuffix.ExactRule => "exact"
    @moonsuffix.WildcardRule => "wildcard"
    @moonsuffix.ExceptionRule => "exception"
  }
}

///|
fn idna_section_name(section : @moonsuffix.RuleSection) -> String {
  match section {
    @moonsuffix.UnsectionedRule => "unsectioned"
    @moonsuffix.IcannSection => "ICANN"
    @moonsuffix.PrivateSection => "PRIVATE"
  }
}

///|
/// Export all Unicode inputs and A-label outcomes as deterministic CSV.
pub fn IdnaBatchReport::to_csv(self : IdnaBatchReport) -> String {
  let output = StringBuilder()
  output.write_string(
    "\"index\",\"input\",\"status\",\"normalized_domain\",\"public_suffix\",\"registrable_domain\",\"matched_rule\",\"rule_kind\",\"rule_section\",\"error\"\n",
  )
  for item in self.items_ {
    let fields = match item.result_ {
      Ok(result) => {
        let section = match result.rule_section() {
          Some(value) => idna_section_name(value)
          None => ""
        }
        [
          item.index_.to_string(),
          item.input_,
          "ok",
          result.normalized_domain(),
          result.public_suffix(),
          result.registrable_domain().unwrap_or(""),
          result.matched_rule(),
          idna_rule_kind_name(result.rule_kind()),
          section,
          "",
        ]
      }
      Err(error) =>
        [
          item.index_.to_string(),
          item.input_,
          "error",
          "",
          "",
          "",
          "",
          "",
          "",
          error.message(),
        ]
    }
    idna_csv_row(output, fields)
  }
  output.to_string()
}
