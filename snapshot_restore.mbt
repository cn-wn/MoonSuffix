///|
/// A stored snapshot whose PSL text or manifest cannot be trusted.
pub(all) enum SnapshotLoadError {
  InvalidManifest(String)
  InvalidRevisionEncoding
  InvalidDigest(String)
  InvalidRuleCount(String)
  InvalidSnapshotRules(ListParseError)
  NonCanonicalPsl
  DigestMismatch(String, String)
  RuleCountMismatch(Int, Int)
} derive(Eq, Debug)

///|
pub fn SnapshotLoadError::message(self : SnapshotLoadError) -> String {
  match self {
    InvalidManifest(reason) => "invalid snapshot manifest: \{reason}"
    InvalidRevisionEncoding =>
      "invalid snapshot manifest: source revision is not canonical percent-encoded UTF-8"
    InvalidDigest(digest) =>
      "invalid snapshot manifest: '\{digest}' is not a lowercase SHA-256 digest"
    InvalidRuleCount(count) =>
      "invalid snapshot manifest: '\{count}' is not a canonical rule count"
    InvalidSnapshotRules(error) =>
      "invalid snapshot PSL text: \{error.message()}"
    NonCanonicalPsl => "snapshot PSL text is not in canonical form"
    DigestMismatch(expected, actual) =>
      "snapshot digest mismatch: manifest has \{expected}, PSL text has \{actual}"
    RuleCountMismatch(expected, actual) =>
      "snapshot rule-count mismatch: manifest has \{expected}, PSL text has \{actual}"
  }
}

///|
fn hex_value(character : UInt16) -> Int? {
  if character >= 0x30 && character <= 0x39 {
    Some(character.to_int() - 0x30)
  } else if character >= 0x61 && character <= 0x66 {
    Some(character.to_int() - 0x61 + 10)
  } else {
    None
  }
}

///|
fn decode_manifest_revision(
  encoded : String,
) -> Result[String, SnapshotLoadError] {
  let bytes : Array[Byte] = []
  let mut index = 0
  while index < encoded.length() {
    let character = encoded[index]
    if character == '%' {
      if index + 2 >= encoded.length() {
        return Err(InvalidRevisionEncoding)
      }
      let high = match hex_value(encoded[index + 1]) {
        Some(value) => value
        None => return Err(InvalidRevisionEncoding)
      }
      let low = match hex_value(encoded[index + 2]) {
        Some(value) => value
        None => return Err(InvalidRevisionEncoding)
      }
      bytes.push((high * 16 + low).to_byte())
      index = index + 3
    } else {
      let value = character.to_int()
      let unreserved = (character >= 'A' && character <= 'Z') ||
        (character >= 'a' && character <= 'z') ||
        (character >= '0' && character <= '9') ||
        character == '-' ||
        character == '.' ||
        character == '_' ||
        character == '~'
      if !unreserved || value > 0x7f {
        return Err(InvalidRevisionEncoding)
      }
      bytes.push(value.to_byte())
      index = index + 1
    }
  }
  let decoded = Ok(@utf8.decode(Bytes::from_array(bytes).view())) catch {
    _ => Err(InvalidRevisionEncoding)
  }
  match decoded {
    Ok(revision) =>
      if manifest_escape(revision) == encoded {
        Ok(revision)
      } else {
        Err(InvalidRevisionEncoding)
      }
    Err(error) => Err(error)
  }
}

///|
fn parse_rule_count(text : String) -> Result[Int, SnapshotLoadError] {
  if text.length() == 0 {
    return Err(InvalidRuleCount(text))
  }
  let mut value = 0
  for character in text {
    if character < '0' || character > '9' {
      return Err(InvalidRuleCount(text))
    }
    let digit = character.to_int() - '0'.to_int()
    if value > (0x7fffffff - digit) / 10 {
      return Err(InvalidRuleCount(text))
    }
    value = value * 10 + digit
  }
  if value.to_string() != text {
    Err(InvalidRuleCount(text))
  } else {
    Ok(value)
  }
}

///|
fn valid_sha256_digest(digest : String) -> Bool {
  if digest.length() != 64 {
    return false
  }
  for character in digest {
    if !((character >= '0' && character <= '9') ||
      (character >= 'a' && character <= 'f')) {
      return false
    }
  }
  true
}

///|
fn manifest_field(line : String, prefix : String) -> String? {
  if line.has_prefix(prefix) {
    Some(line[prefix.length():].to_owned())
  } else {
    None
  }
}

///|
/// Restore a snapshot from canonical PSL text and its stored manifest.
///
/// The manifest structure, revision encoding, digest, rule count, PSL syntax,
/// and canonical byte representation are all verified before a `Snapshot` is
/// returned.
pub fn Snapshot::restore(
  psl_text : String,
  manifest : String,
) -> Result[Snapshot, SnapshotLoadError] {
  let lines : Array[String] = []
  for line in manifest.split("\n") {
    lines.push(line.to_owned())
  }
  if lines.length() != 5 || lines[4] != "" {
    return Err(InvalidManifest("expected four LF-terminated fields"))
  }
  if lines[0] != "format=moonsuffix-snapshot-v1" {
    return Err(InvalidManifest("unsupported format"))
  }
  let encoded_revision = match manifest_field(lines[1], "source_revision=") {
    Some(value) => value
    None => return Err(InvalidManifest("missing source_revision field"))
  }
  let expected_digest = match manifest_field(lines[2], "psl_sha256=") {
    Some(value) => value
    None => return Err(InvalidManifest("missing psl_sha256 field"))
  }
  let encoded_count = match manifest_field(lines[3], "rule_count=") {
    Some(value) => value
    None => return Err(InvalidManifest("missing rule_count field"))
  }
  let revision = match decode_manifest_revision(encoded_revision) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if !valid_sha256_digest(expected_digest) {
    return Err(InvalidDigest(expected_digest))
  }
  let expected_count = match parse_rule_count(encoded_count) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let suffixes = match SuffixList::parse(psl_text) {
    Ok(value) => value
    Err(error) => return Err(InvalidSnapshotRules(error))
  }
  if suffixes.to_psl_text() != psl_text {
    return Err(NonCanonicalPsl)
  }
  let actual_digest = sha256_hex(psl_text)
  if actual_digest != expected_digest {
    return Err(DigestMismatch(expected_digest, actual_digest))
  }
  let actual_count = suffixes.rule_count()
  if actual_count != expected_count {
    return Err(RuleCountMismatch(expected_count, actual_count))
  }
  Ok({
    source_revision_: revision,
    psl_text_: psl_text,
    sha256_: actual_digest,
    rule_count_: actual_count,
  })
}
