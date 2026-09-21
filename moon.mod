name = "cn-wn/moonsuffix"

version = "0.1.0"

readme = "README.md"

repository = "https://github.com/cn-wn/MoonSuffix"

license = "Apache-2.0"

keywords = [ "public-suffix", "domain", "etld", "cookie", "wasm" ]

preferred_target = "wasm-gc"

supported_targets = "+js+wasm+wasm-gc+native"

description = "A portable Public Suffix List engine for registrable-domain decisions in MoonBit."

import {
  "moonbitlang/async@0.22.1",
}
