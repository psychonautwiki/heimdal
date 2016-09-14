#![macro_use]
extern crate neon;
extern crate crypto;
extern crate rand;

use neon::js::binary::JsBuffer;
use neon::js::error::*;
use neon::js::{Value};

use util::*;

declare_types! {
    pub class Curve25519 as Curve25519 for () {
        init(_) {
            println!("Warning: this feature is not tested.");

            Ok(())
        }

        method curve25519(mut call) {
            let n = try!(call.check_argument::<JsBuffer>(0));
            let p = try!(call.check_argument::<JsBuffer>(1));

            let scope = call.scope;

            let n_slice: Vec<u8> = buf_to_vec(n);
            let p_slice: Vec<u8> = buf_to_vec(p);

            assert_buf_with_size!(scope, p_slice, "p", 32);

            let key = crypto::curve25519::curve25519(
                &n_slice,
                &p_slice
            );

            let mut jsb_key = try!(JsBuffer::new(scope, 32));

            buf_copy_from_slice(&key, &mut jsb_key);

            Ok(jsb_key.as_value(scope))
        }

        method curve25519_base(mut call) {
            let x = try!(call.check_argument::<JsBuffer>(0));

            let scope = call.scope;

            let x_slice: Vec<u8> = buf_to_vec(x);

            let key = crypto::curve25519::curve25519_base(
                &x_slice
            );

            let mut jsb_key = try!(JsBuffer::new(scope, 32));

            buf_copy_from_slice(&key, &mut jsb_key);

            Ok(jsb_key.as_value(scope))
        }
    }
}