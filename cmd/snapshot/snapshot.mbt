///|
struct SnapshotConfig {
  source_path : String
  output_path : String
  revision : String
  idna : Bool
}

///|
fn snapshot_command() -> @argparse.Command {
  @argparse.Command(
    "moonsuffix-snapshot",
    about="Build a verified single-file PSL snapshot from a local list",
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
        "output-bundle",
        about="Path for a new snapshot bundle; existing files are not overwritten",
        num_args=@argparse.ValueRange::single(),
      ),
    ],
  )
}

///|
fn parse_snapshot_config(argv : ArrayView[String]) -> SnapshotConfig raise {
  let matches = snapshot_command().parse(argv~)
  guard matches.values
    is {
      "source-psl": [source_path],
      "output-bundle": [output_path],
      "revision": [revision],
      ..
    } else {
    fail("missing required snapshot input")
  }
  {
    source_path,
    output_path,
    revision,
    idna: matches.flags.get("idna").unwrap_or(false),
  }
}

///|
fn build_snapshot_bundle(
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
  let bundle = list.snapshot(revision).bundle_text()
  match @moonsuffix.Snapshot::restore_bundle_text(bundle) {
    Ok(_) => Ok(bundle)
    Err(error) => Err(error.message())
  }
}
