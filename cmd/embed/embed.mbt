///|
struct EmbedConfig {
  source_path : String
  output_path : String
  revision : String
  idna : Bool
}

///|
fn embed_command() -> @argparse.Command {
  @argparse.Command(
    "moonsuffix-embed",
    about="Generate a portable MoonBit source file from a pinned PSL",
    flags=[
      @argparse.FlagArg(
        "idna",
        about="Normalize Unicode PSL rules to A-labels using UTS #46",
      ),
    ],
    options=[
      @argparse.OptionArg(
        "revision",
        about="Opaque revision label identifying the source PSL",
        required=true,
      ),
    ],
    positionals=[
      @argparse.PositionArg(
        "source-psl",
        about="Path to the source PSL text",
        num_args=@argparse.ValueRange::single(),
      ),
      @argparse.PositionArg(
        "output-source",
        about="Path for a new MoonBit source file; existing files are not overwritten",
        num_args=@argparse.ValueRange::single(),
      ),
    ],
  )
}

///|
fn parse_embed_config(argv : ArrayView[String]) -> EmbedConfig raise {
  let matches = embed_command().parse(argv~)
  guard matches.values
    is {
      "source-psl": [source_path],
      "output-source": [output_path],
      "revision": [revision],
      ..
    } else {
    fail("missing required embedded-source input")
  }
  {
    source_path,
    output_path,
    revision,
    idna: matches.flags.get("idna").unwrap_or(false),
  }
}

///|
fn build_embedded_source(
  source : String,
  revision : String,
  idna : Bool,
) -> Result[String, String] {
  let list = if idna {
    match @suffix_idna.parse_psl(source) {
      Ok(value) => value
      Err(error) => return Err(error.message())
    }
  } else {
    match @moonsuffix.SuffixList::parse(source) {
      Ok(value) => value
      Err(error) => return Err(error.message())
    }
  }
  let snapshot = list.snapshot(revision)
  match @moonsuffix.Snapshot::restore_bundle_text(snapshot.bundle_text()) {
    Ok(_) => Ok(snapshot.to_moonbit_source())
    Err(error) => Err(error.message())
  }
}
