///|
/// One ordered result in a batch hostname lookup.
pub struct BatchItem {
  index_ : Int
  input_ : String
  result_ : Result[Lookup, DomainError]
}

///|
pub fn BatchItem::index(self : BatchItem) -> Int {
  self.index_
}

///|
pub fn BatchItem::input(self : BatchItem) -> String {
  self.input_
}

///|
pub fn BatchItem::result(self : BatchItem) -> Result[Lookup, DomainError] {
  self.result_
}

///|
/// Ordered results and summary counts for a recoverable batch lookup.
pub struct BatchReport {
  items_ : ReadOnlyArray[BatchItem]
  success_count_ : Int
  error_count_ : Int
}

///|
pub fn BatchReport::items(self : BatchReport) -> ReadOnlyArray[BatchItem] {
  self.items_
}

///|
pub fn BatchReport::length(self : BatchReport) -> Int {
  self.items_.length()
}

///|
pub fn BatchReport::success_count(self : BatchReport) -> Int {
  self.success_count_
}

///|
pub fn BatchReport::error_count(self : BatchReport) -> Int {
  self.error_count_
}

///|
/// Look up hostnames in input order with browser-style defaults.
///
/// Invalid inputs are retained as row-level errors and do not stop the batch.
pub fn SuffixList::lookup_batch(
  self : SuffixList,
  domains : Array[String],
) -> BatchReport {
  self.lookup_batch_with_options(domains, LookupOptions::browser_default())
}

///|
/// Look up hostnames in input order with explicit lookup options.
///
/// Invalid inputs are retained as row-level errors and do not stop the batch.
pub fn SuffixList::lookup_batch_with_options(
  self : SuffixList,
  domains : Array[String],
  options : LookupOptions,
) -> BatchReport {
  let items : Array[BatchItem] = []
  let mut success_count = 0
  let mut error_count = 0
  for index, domain in domains {
    let result = self.lookup_with_options(domain, options)
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
fn rule_kind_name(kind : RuleKind) -> String {
  match kind {
    DefaultRule => "default"
    ExactRule => "exact"
    WildcardRule => "wildcard"
    ExceptionRule => "exception"
  }
}

///|
fn csv_field(text : String) -> String {
  let output = StringBuilder()
  output.write_char('"')
  for character in text {
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
fn write_csv_row(output : StringBuilder, fields : Array[String]) -> Unit {
  for index, field in fields {
    if index > 0 {
      output.write_char(',')
    }
    output.write_string(csv_field(field))
  }
  output.write_char('\n')
}

///|
/// Export the complete batch to deterministic CSV with RFC 4180-style field
/// quoting.
///
/// All fields are quoted, the input order is preserved, and output uses LF line
/// endings with a final newline.
pub fn BatchReport::to_csv(self : BatchReport) -> String {
  let output = StringBuilder()
  output.write_string(
    "\"index\",\"input\",\"status\",\"normalized_domain\",\"public_suffix\",\"registrable_domain\",\"matched_rule\",\"rule_kind\",\"rule_section\",\"error\"\n",
  )
  for item in self.items_ {
    let fields = match item.result_ {
      Ok(result) => {
        let registrable = match result.registrable_domain() {
          Some(value) => value
          None => ""
        }
        let section = match result.rule_section() {
          Some(value) => section_name(value)
          None => ""
        }
        [
          item.index_.to_string(),
          item.input_,
          "ok",
          result.normalized_domain(),
          result.public_suffix(),
          registrable,
          result.matched_rule(),
          rule_kind_name(result.rule_kind()),
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
    write_csv_row(output, fields)
  }
  output.to_string()
}
