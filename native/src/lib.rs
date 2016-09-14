#[macro_use]
extern crate neon;
extern crate crypto;
extern crate rand;

use neon::js::class::{JsClass, Class};
use neon::js::{JsFunction, Object};
use neon::mem::Handle;

#[macro_use]
mod util;

/* auth */
pub mod ed25519;
use ed25519::Ed25519;

/* scalarmult */
pub mod curve25519;
use curve25519::Curve25519;

/* encryption */
pub mod chacha20;
use chacha20::ChaCha20;

register_module!(m, {
    let class: Handle<JsClass<Ed25519>> = try!(Ed25519::class(m.scope));
    let constructor: Handle<JsFunction<Ed25519>> = try!(class.constructor(m.scope));
    try!(m.exports.set("Ed25519", constructor));

    let class: Handle<JsClass<Curve25519>> = try!(Curve25519::class(m.scope));
    let constructor: Handle<JsFunction<Curve25519>> = try!(class.constructor(m.scope));
    try!(m.exports.set("Curve25519", constructor));

    let class: Handle<JsClass<ChaCha20>> = try!(ChaCha20::class(m.scope));
    let constructor: Handle<JsFunction<ChaCha20>> = try!(class.constructor(m.scope));
    try!(m.exports.set("ChaCha20", constructor));

    Ok(())
});
