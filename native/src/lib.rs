#[macro_use]
extern crate neon;
extern crate crypto;
extern crate rand;

use rand::Rng;

use neon::js::binary::JsBuffer;
use neon::js::class::{JsClass, Class};
use neon::js::{JsFunction, JsObject, Object, Value};
use neon::mem::Handle;

mod util;
use util::*;

mod ed25519;
use ed25519::Ed25519;

register_module!(m, {
    let class: Handle<JsClass<Ed25519>> = try!(Ed25519::class(m.scope));
    let constructor: Handle<JsFunction<Ed25519>> = try!(class.constructor(m.scope));
    try!(m.exports.set("Ed25519", constructor));

    Ok(())
});
