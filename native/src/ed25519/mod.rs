#![macro_use]
extern crate neon;
extern crate crypto;
extern crate rand;

use rand::Rng;

use neon::vm::Throw;
use neon::js::binary::JsBuffer;
use neon::js::class::{JsClass, Class};
use neon::js::error::*;
use neon::js::{JsFunction, JsObject, Object, Value};
use neon::mem::Handle;

use util::*;

macro_rules! assert_len {
    ($slice:expr, $len:expr) => {{
        assert!($slice.len() == $len);
    }};
}

declare_types! {
    pub class Ed25519 as Ed25519 for () {
        init(_) {
            Ok(())
        }

        method exchange(mut call) {
            let bob_public = try!(call.check_argument::<JsBuffer>(0));
            let alice_private = try!(call.check_argument::<JsBuffer>(1));

            let scope = call.scope;

            neon::js::error::throw(scope,try!(JsError::new(scope, Kind::RangeError, "Fsodakd")));

            let bob_public_slice: Vec<u8> = buf_to_vec(bob_public);
            let alice_private_slice: Vec<u8> = buf_to_vec(alice_private);

            assert_len!(bob_public_slice, 32);
            assert_len!(alice_private_slice, 64);

            let shared_key = crypto::ed25519::exchange(
                &bob_public_slice,
                &alice_private_slice
            );

            let mut jsb_shared_key = try!(JsBuffer::new(scope, shared_key.len() as u32));

            buf_copy_from_slice(&shared_key, &mut jsb_shared_key);

            let _ = (1..1000).collect::<Vec<i32>>();

            Ok(jsb_shared_key.as_value(scope))
        }

        method keypair(call) {
            let scope = call.scope;

            let mut seed = [0u8; 32];

            let mut rng = rand::OsRng::new().unwrap();
            rng.fill_bytes(&mut seed);

            let (kp_private, kp_public) = crypto::ed25519::keypair(&seed);

            let outobj: Handle<JsObject> = JsObject::new(scope);

            let mut jsb_kp_private = try!(JsBuffer::new(scope, kp_private.len() as u32));

            buf_copy_from_slice(&kp_private, &mut jsb_kp_private);

            let mut jsb_kp_public = try!(JsBuffer::new(scope, kp_public.len() as u32));

            buf_copy_from_slice(&kp_public, &mut jsb_kp_public);

            let _ = outobj.set("private", jsb_kp_private);
            let _ = outobj.set("public", jsb_kp_public);

            Ok(outobj.as_value(scope))
        }

        method signature(mut call) {
            let message = try!(call.check_argument::<JsBuffer>(0));
            let alice_private = try!(call.check_argument::<JsBuffer>(1));

            let scope = call.scope;

            let message_slice: Vec<u8> = buf_to_vec(message);
            let alice_private_slice: Vec<u8> = buf_to_vec(alice_private);

            let shared_key = crypto::ed25519::exchange(
                &message_slice,
                &alice_private_slice
            );

            let mut jsb_shared_key = try!(JsBuffer::new(scope, shared_key.len() as u32));

            buf_copy_from_slice(&shared_key, &mut jsb_shared_key);

            let _ = (1..1000).collect::<Vec<i32>>();

            Ok(jsb_shared_key.as_value(scope))
        }
    }
}