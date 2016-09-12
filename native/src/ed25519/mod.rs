#![macro_use]
extern crate neon;
extern crate crypto;
extern crate rand;

use rand::Rng;

use neon::js::binary::JsBuffer;
use neon::js::error::*;
use neon::js::{JsBoolean, JsObject, Object, Value};
use neon::mem::Handle;

use util::*;

declare_types! {
    pub class Ed25519 as Ed25519 for () {
        init(_) {
            Ok(())
        }

        method exchange(mut call) {
            let bob_public = try!(call.check_argument::<JsBuffer>(0));
            let alice_private = try!(call.check_argument::<JsBuffer>(1));

            let scope = call.scope;

            let bob_public_slice: Vec<u8> = buf_to_vec(bob_public);
            let alice_private_slice: Vec<u8> = buf_to_vec(alice_private);

            assert_buf_with_size!(scope, bob_public_slice, "public key", 32);
            assert_buf_with_size!(scope, alice_private_slice, "private key", 64);

            let shared_key = crypto::ed25519::exchange(
                &bob_public_slice,
                &alice_private_slice
            );

            let mut jsb_shared_key = try!(JsBuffer::new(scope, shared_key.len() as u32));

            buf_copy_from_slice(&shared_key, &mut jsb_shared_key);

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

            let signature_slice: [u8; 64] = crypto::ed25519::signature(
                &message_slice,
                &alice_private_slice
            );

            let mut signature_buf = try!(JsBuffer::new(scope, signature_slice.len() as u32));

            buf_copy_from_slice(&signature_slice, &mut signature_buf);

            Ok(signature_buf.as_value(scope))
        }


        method verify(mut call) {
            let message = try!(call.check_argument::<JsBuffer>(0));
            let alice_public = try!(call.check_argument::<JsBuffer>(1));
            let alice_signature = try!(call.check_argument::<JsBuffer>(2));

            let scope = call.scope;

            let message_slice: Vec<u8> = buf_to_vec(message);
            let alice_public_slice: Vec<u8> = buf_to_vec(alice_public);
            let alice_signature_slice: Vec<u8> = buf_to_vec(alice_signature);

            assert_buf_with_size!(scope, alice_public_slice, "public key", 32);
            assert_buf_with_size!(scope, alice_signature_slice, "signature", 64);

            let verify_signature: bool = crypto::ed25519::verify(
                &message_slice,
                &alice_public_slice,
                &alice_signature_slice
            );

            let verify_signature_jsbool = JsBoolean::new(scope, verify_signature);

            Ok(verify_signature_jsbool.as_value(scope))
        }
    }
}