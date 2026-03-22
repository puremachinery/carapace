use std::path::PathBuf;

use wit_component::{dummy_module, embed_component_metadata, ComponentEncoder, StringEncoding};
use wit_parser::{ManglingAndAbi, Resolve};

pub(crate) fn tool_plugin_component_bytes() -> Vec<u8> {
    let wit_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tool-plugin.wit");
    let mut resolve = Resolve::default();
    let (pkg, _) = resolve.push_path(&wit_path).expect("load plugin WIT");
    let world = resolve
        .select_world(&[pkg], Some("tool-plugin"))
        .expect("select tool-plugin world");
    let mut module = dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8)
        .expect("embed component metadata");
    ComponentEncoder::default()
        .module(&module)
        .expect("attach core module")
        .validate(true)
        .encode()
        .expect("encode tool plugin component")
}
