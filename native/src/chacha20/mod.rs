#![macro_use]
extern crate neon;
extern crate crypto;
extern crate rand;

use rand::Rng;

use neon::js::binary::JsBuffer;
use neon::js::error::*;
use neon::js::{JsBoolean, JsObject, Object, Value};
use neon::mem::Handle;
use neon::vm::Lock;

use crypto::symmetriccipher::SynchronousStreamCipher;

use util::*;

declare_types! {
    pub class ChaCha20 as ChaCha20 for crypto::chacha20::ChaCha20 {
        init(mut call) {
            let key = try!(call.check_argument::<JsBuffer>(0));
            let nonce = try!(call.check_argument::<JsBuffer>(1));

            let scope = call.scope;

            let key_slice: Vec<u8> = buf_to_vec(key);
            let nonce_slice: Vec<u8> = buf_to_vec(nonce);

            assert_or_throw!(scope, key_slice.len() == 16 || key_slice.len() == 32, "key must have a length of 16 or 32");
            assert_or_throw!(scope, nonce_slice.len() == 8 || nonce_slice.len() == 12, "nonce must have a length of 8 or 12");

            Ok(crypto::chacha20::ChaCha20::new(&key_slice, &nonce_slice))
        }

        method process(mut call) {
            let input = try!(call.check_argument::<JsBuffer>(0));

            let scope = call.scope;

            let input_slice: Vec<u8> = buf_to_vec(input);

            let out_slice = call.arguments.this(scope).grab(|chacha20| {
                let mut outbuf = vec!(0u8; input_slice.len());

                chacha20.process(&input_slice, &mut outbuf);

                outbuf
            });

            let mut jsb_out = try!(JsBuffer::new(scope, out_slice.len() as u32));

            buf_copy_from_slice(&out_slice, &mut jsb_out);

            Ok(jsb_out.as_value(scope))
        }
    }
}