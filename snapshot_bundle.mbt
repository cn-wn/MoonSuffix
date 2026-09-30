///|
/// Store the versioned manifest and canonical PSL in one deterministic file.
///
/// One empty line separates the four-field manifest from the PSL text. The
/// revision and digest are verified when the bundle is restored.
pub fn Snapshot::bundle_text(self : Snapshot) -> String {
  self.manifest_text() + "\n" + self.psl_text()
}

///|
/// Restore and verify a single-file snapshot bundle.
///
/// The first blank line ends the manifest. The remainder must be the exact
/// canonical PSL bytes whose digest and rule count appear in the manifest.
pub fn Snapshot::restore_bundle_text(
  bundle : String,
) -> Result[Snapshot, SnapshotLoadError] {
  match Snapshot::restore_compiled_bundle_text(bundle) {
    Ok((snapshot, _)) => Ok(snapshot)
    Err(error) => Err(error)
  }
}

///|
/// Restore a verified bundle together with its already parsed rule table.
/// This avoids parsing the PSL a second time when the caller needs lookups.
pub fn Snapshot::restore_compiled_bundle_text(
  bundle : String,
) -> Result[(Snapshot, SuffixList), SnapshotLoadError] {
  let separator = match bundle.find("\n\n") {
    Some(index) => index
    None => return Err(InvalidManifest("missing bundle separator"))
  }
  let manifest = bundle[:separator + 1].to_owned()
  let psl_text = bundle[separator + 2:].to_owned()
  restore_compiled(psl_text, manifest)
}
