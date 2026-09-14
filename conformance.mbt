///|
/// An invalid non-comment line in a PSL conformance test file.
pub(all) enum ConformanceParseError {
  InvalidConformanceCase(Int, String, String)
} derive(Eq, Debug)

///|
pub fn ConformanceParseError::message(self : ConformanceParseError) -> String {
  match self {
    InvalidConformanceCase(line, text, reason) =>
      "invalid PSL conformance case on line \{line} ('\{text}'): \{reason}"
  }
}

///|
/// The observable result produced for one conformance input.
pub(all) enum ConformanceActual {
  NullInput
  RejectedDomain(DomainError)
  NoRegistrableDomain
  RegistrableDomain(String)
} derive(Eq, Debug)

///|
/// One conformance case whose actual result differs from its expectation.
pub struct ConformanceFailure {
  line_ : Int
  input_ : String?
  expected_ : String?
  actual_ : ConformanceActual
}

///|
pub fn ConformanceFailure::line(self : ConformanceFailure) -> Int {
  self.line_
}

///|
pub fn ConformanceFailure::input(self : ConformanceFailure) -> String? {
  self.input_
}

///|
pub fn ConformanceFailure::expected(self : ConformanceFailure) -> String? {
  self.expected_
}

///|
pub fn ConformanceFailure::actual(
  self : ConformanceFailure,
) -> ConformanceActual {
  self.actual_
}

///|
/// Summary and ordered failures from an upstream-style PSL conformance run.
pub struct ConformanceReport {
  total_count_ : Int
  passed_count_ : Int
  failures_ : ReadOnlyArray[ConformanceFailure]
}

///|
pub fn ConformanceReport::total_count(self : ConformanceReport) -> Int {
  self.total_count_
}

///|
pub fn ConformanceReport::passed_count(self : ConformanceReport) -> Int {
  self.passed_count_
}

///|
pub fn ConformanceReport::failed_count(self : ConformanceReport) -> Int {
  self.failures_.length()
}

///|
pub fn ConformanceReport::failures(
  self : ConformanceReport,
) -> ReadOnlyArray[ConformanceFailure] {
  self.failures_
}

///|
pub fn ConformanceReport::is_success(self : ConformanceReport) -> Bool {
  self.failures_.length() == 0
}

///|
fn parse_case_value(value : String) -> Result[String?, String] {
  let token = value.trim().to_owned()
  if token == "null" {
    return Ok(None)
  }
  if token.length() < 2 || token[0] != '\'' || token[token.length() - 1] != '\'' {
    return Err("expected null or a single-quoted domain")
  }
  let domain = token[1:token.length() - 1].to_owned()
  if domain.contains("'") || domain.contains("\\") {
    return Err("quoted domains must not contain escapes or quotes")
  }
  Ok(Some(domain))
}

///|
fn parse_conformance_case(
  line_number : Int,
  line : String,
) -> Result[(String?, String?)?, ConformanceParseError] {
  let trimmed = line.trim().to_owned()
  if trimmed == "" || trimmed.has_prefix("//") {
    return Ok(None)
  }
  let prefix = "checkPublicSuffix("
  if !trimmed.has_prefix(prefix) || !trimmed.has_suffix(");") {
    return Err(
      InvalidConformanceCase(
        line_number, trimmed, "expected checkPublicSuffix(input, expected);",
      ),
    )
  }
  let arguments = trimmed[prefix.length():trimmed.length() - 2].to_owned()
  let comma = match arguments.find(",") {
    Some(value) => value
    None =>
      return Err(
        InvalidConformanceCase(
          line_number, trimmed, "expected two comma-separated arguments",
        ),
      )
  }
  if arguments[comma + 1:].contains(",") {
    return Err(
      InvalidConformanceCase(
        line_number, trimmed, "expected exactly two arguments",
      ),
    )
  }
  let input = match parse_case_value(arguments[:comma].to_owned()) {
    Ok(value) => value
    Err(reason) =>
      return Err(InvalidConformanceCase(line_number, trimmed, reason))
  }
  let expected = match parse_case_value(arguments[comma + 1:].to_owned()) {
    Ok(value) => value
    Err(reason) =>
      return Err(InvalidConformanceCase(line_number, trimmed, reason))
  }
  Ok(Some((input, expected)))
}

///|
fn SuffixList::conformance_actual(
  self : SuffixList,
  input : String?,
) -> ConformanceActual {
  match input {
    None => NullInput
    Some(domain) =>
      match self.registrable_domain(domain) {
        Err(error) => RejectedDomain(error)
        Ok(None) => NoRegistrableDomain
        Ok(Some(value)) => RegistrableDomain(value)
      }
  }
}

///|
fn conformance_matches(expected : String?, actual : ConformanceActual) -> Bool {
  match (expected, actual) {
    (None, NullInput)
    | (None, RejectedDomain(_))
    | (None, NoRegistrableDomain) => true
    (Some(wanted), RegistrableDomain(found)) => wanted == found
    _ => false
  }
}

///|
/// Run `checkPublicSuffix(input, expected);` cases in upstream file order.
///
/// Blank and `//` comment lines are ignored. An expected `null` accepts either
/// a rejected domain or a valid public suffix with no registrable domain, while
/// the report preserves that distinction for failed non-null expectations.
pub fn SuffixList::verify_psl_test_file(
  self : SuffixList,
  test_text : String,
) -> Result[ConformanceReport, ConformanceParseError] {
  let failures : Array[ConformanceFailure] = []
  let mut total_count = 0
  let mut passed_count = 0
  let mut line_number = 0
  for line in test_text.split("\n") {
    line_number = line_number + 1
    let parsed = match parse_conformance_case(line_number, line.to_owned()) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    match parsed {
      None => ()
      Some((input, expected)) => {
        total_count = total_count + 1
        let actual = self.conformance_actual(input)
        if conformance_matches(expected, actual) {
          passed_count = passed_count + 1
        } else {
          failures.push({
            line_: line_number,
            input_: input,
            expected_: expected,
            actual_: actual,
          })
        }
      }
    }
  }
  Ok({
    total_count_: total_count,
    passed_count_: passed_count,
    failures_: ReadOnlyArray::from_array(failures),
  })
}

///|
fn conformance_value_text(value : String?) -> String {
  match value {
    None => "null"
    Some(text) => text
  }
}

///|
fn conformance_actual_text(actual : ConformanceActual) -> String {
  match actual {
    NullInput => "null_input"
    RejectedDomain(error) => "rejected: " + error.message()
    NoRegistrableDomain => "no_registrable_domain"
    RegistrableDomain(domain) => domain
  }
}

///|
/// Export failed cases in source order as deterministic, fully quoted CSV.
pub fn ConformanceReport::to_csv(self : ConformanceReport) -> String {
  let output = StringBuilder()
  output.write_string("\"line\",\"input\",\"expected\",\"actual\"\n")
  for failure in self.failures_ {
    write_csv_row(output, [
      failure.line_.to_string(),
      conformance_value_text(failure.input_),
      conformance_value_text(failure.expected_),
      conformance_actual_text(failure.actual_),
    ])
  }
  output.to_string()
}
