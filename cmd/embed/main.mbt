///|
async fn main {
  let config = parse_embed_config(@env.args()[1:])
  let source = @fs.read_file(config.source_path).text()
  let generated = match
    build_embedded_source(source, config.revision, config.idna) {
    Ok(value) => value
    Err(error) => fail(error)
  }
  @fs.write_file(config.output_path, generated, create_mode=CreateNew)
}
