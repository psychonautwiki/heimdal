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

            let key_slice: Vec<u8> = buf_to_vec(key);
            let nonce_slice: Vec<u8> = buf_to_vec(nonce);

            Ok(crypto::chacha20::ChaCha20::new(&key_slice, &nonce_slice))
        }

        method process(mut call) {
            let input = try!(call.check_argument::<JsBuffer>(0));

            let scope = call.scope;

            let input_slice: Vec<u8> = buf_to_vec(input);

            let out_slice = call.arguments.this(scope).grab(|chacha20| {
                let mut outbuf = Vec::with_capacity(input_slice.len());

                chacha20.process(&input_slice, &mut outbuf);

                outbuf
            });

            let mut jsb_out = try!(JsBuffer::new(scope, out_slice.len() as u32));

            buf_copy_from_slice(&out_slice, &mut jsb_out);

            Ok(jsb_out.as_value(scope))
        }
    }
}