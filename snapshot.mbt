///|
let sha256_round_constants : Array[UInt] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
fn rotate_right(value : UInt, count : Int) -> UInt {
  (value >> count) | (value << (32 - count))
}

///|
fn sha256_hex(text : String) -> String {
  let input = @utf8.encode(text)
  let padded : Array[Byte] = []
  for byte in input {
    padded.push(byte)
  }
  let bit_length = input.length().to_int64().reinterpret_as_uint64() * 8UL
  padded.push(b'\x80')
  while padded.length() % 64 != 56 {
    padded.push(b'\x00')
  }
  for shift in [56, 48, 40, 32, 24, 16, 8, 0] {
    padded.push((bit_length >> shift).to_byte())
  }
  let state : Array[UInt] = [
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU,
    0x1f83d9abU, 0x5be0cd19U,
  ]
  for offset = 0; offset < padded.length(); offset = offset + 64 {
    let schedule = Array::make(64, 0U)
    for i in 0..<16 {
      let start = offset + i * 4
      schedule[i] = (padded[start].to_uint() << 24) |
        (padded[start + 1].to_uint() << 16) |
        (padded[start + 2].to_uint() << 8) |
        padded[start + 3].to_uint()
    }
    for i in 16..<64 {
      let first = schedule[i - 15]
      let second = schedule[i - 2]
      let sigma0 = rotate_right(first, 7) ^
        rotate_right(first, 18) ^
        (first >> 3)
      let sigma1 = rotate_right(second, 17) ^
        rotate_right(second, 19) ^
        (second >> 10)
      schedule[i] = schedule[i - 16] + sigma0 + schedule[i - 7] + sigma1
    }
    let mut a = state[0]
    let mut b = state[1]
    let mut c = state[2]
    let mut d = state[3]
    let mut e = state[4]
    let mut f = state[5]
    let mut g = state[6]
    let mut h = state[7]
    for i in 0..<64 {
      let sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)
      let choice = (e & f) ^ (e.lnot() & g)
      let temporary1 = h +
        sum1 +
        choice +
        sha256_round_constants[i] +
        schedule[i]
      let sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)
      let majority = (a & b) ^ (a & c) ^ (b & c)
      let temporary2 = sum0 + majority
      h = g
      g = f
      f = e
      e = d + temporary1
      d = c
      c = b
      b = a
      a = temporary1 + temporary2
    }
    state[0] = state[0] + a
    state[1] = state[1] + b
    state[2] = state[2] + c
    state[3] = state[3] + d
    state[4] = state[4] + e
    state[5] = state[5] + f
    state[6] = state[6] + g
    state[7] = state[7] + h
  }
  let digest = StringBuilder()
  for word in state {
    digest.write_string((word >> 24).to_byte().to_hex())
    digest.write_string((word >> 16).to_byte().to_hex())
    digest.write_string((word >> 8).to_byte().to_hex())
    digest.write_string(word.to_byte().to_hex())
  }
  digest.to_string()
}

///|
fn manifest_escape(text : String) -> String {
  let escaped = StringBuilder()
  for byte in @utf8.encode(text) {
    let value = byte.to_uint()
    let unreserved = (value >= 0x41U && value <= 0x5aU) ||
      (value >= 0x61U && value <= 0x7aU) ||
      (value >= 0x30U && value <= 0x39U) ||
      value == 0x2dU ||
      value == 0x2eU ||
      value == 0x5fU ||
      value == 0x7eU
    if unreserved {
      escaped.write_char(value.reinterpret_as_int().unsafe_to_char())
    } else {
      escaped.write_char('%')
      escaped.write_string(byte.to_hex())
    }
  }
  escaped.to_string()
}

///|
/// A reproducible canonical PSL snapshot and its provenance metadata.
pub struct Snapshot {
  source_revision_ : String
  psl_text_ : String
  sha256_ : String
  rule_count_ : Int
}

///|
/// Build a snapshot from this rule set and an opaque upstream revision label.
pub fn SuffixList::snapshot(
  self : SuffixList,
  source_revision : String,
) -> Snapshot {
  let psl_text = self.to_psl_text()
  {
    source_revision_: source_revision,
    psl_text_: psl_text,
    sha256_: sha256_hex(psl_text),
    rule_count_: self.rule_count(),
  }
}

///|
pub fn Snapshot::source_revision(self : Snapshot) -> String {
  self.source_revision_
}

///|
pub fn Snapshot::psl_text(self : Snapshot) -> String {
  self.psl_text_
}

///|
pub fn Snapshot::sha256(self : Snapshot) -> String {
  self.sha256_
}

///|
pub fn Snapshot::rule_count(self : Snapshot) -> Int {
  self.rule_count_
}

///|
/// Return a deterministic line-oriented manifest. The source revision is
/// percent-encoded as UTF-8 so arbitrary labels cannot alter its structure.
pub fn Snapshot::manifest_text(self : Snapshot) -> String {
  "format=moonsuffix-snapshot-v1\n" +
  "source_revision=\{manifest_escape(self.source_revision_)}\n" +
  "psl_sha256=\{self.sha256_}\n" +
  "rule_count=\{self.rule_count_}\n"
}
