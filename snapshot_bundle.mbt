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
  let separator = match bundle.find("\n\n") {
    Some(index) => index
    None => return Err(InvalidManifest("missing bundle separator"))
  }
  let manifest = bundle[:separator + 1].to_owned()
  let psl_text = bundle[separator + 2:].to_owned()
  Snapshot::restore(psl_text, manifest)
}
