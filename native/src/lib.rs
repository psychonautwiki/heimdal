#[macro_use]
extern crate neon;
extern crate crypto;
extern crate rand;

use neon::js::class::{JsClass, Class};
use neon::js::{JsFunction, Object};
use neon::mem::Handle;

#[macro_use]
mod util;

pub mod ed25519;
use ed25519::Ed25519;

register_module!(m, {
    let class: Handle<JsClass<Ed25519>> = try!(Ed25519::class(m.scope));
    let constructor: Handle<JsFunction<Ed25519>> = try!(class.constructor(m.scope));
    try!(m.exports.set("Ed25519", constructor));

    Ok(())
});
