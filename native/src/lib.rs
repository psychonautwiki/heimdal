#[macro_use]
extern crate neon;
extern crate crypto;

extern crate rand;

use rand::Rng;

use neon::vm::{Lock, Call, This, FunctionCall, JsResult};
use neon::mem::Handle;
use neon::js::binary::JsBuffer;
use neon::js::{JsObject, Object, JsUndefined, Value};

/*
    fn my_helper_function<'a, S: Scope<'a>>(scope: &'a mut S, obj: Handle<'a, JsObject>) -> JsResult<'a, JsValue> {
        // ...
    }
*/

trait CheckArgument<'a> {
    fn check_argument<V: Value>(&mut self, i: i32) -> JsResult<'a, V>;
}

impl<'a, T: This> CheckArgument<'a> for FunctionCall<'a, T> {
    fn check_argument<V: Value>(&mut self, i: i32) -> JsResult<'a, V> {
        try!(self.arguments.require(self.scope, i)).check::<V>()
    }
}

fn memcpy(data: &[u8], buf: &mut Handle<JsBuffer>) {
    buf.grab(|mut contents| {
        let slice = contents.as_mut_slice();

        for i in 0..slice.len() {
            slice[i] = data[i] as u8;
        }
    });
}

fn c(data: &[u8], buf: &mut Handle<JsBuffer>) {
    buf.grab(|mut contents| {
        let slice = contents.as_mut_slice();

        for i in 0..slice.len() {
            slice[i] = data[i] as u8;
        }
    });
}

fn keypair(call: Call) -> JsResult<JsObject> {
    let scope = call.scope;

    let mut seed = [0u8; 32];

    let mut rng = rand::OsRng::new().unwrap();
    rng.fill_bytes(&mut seed);

    let (kp_private, kp_public) = crypto::ed25519::keypair(&seed);

    let outobj: Handle<JsObject> = JsObject::new(scope);

    let mut jsb_kp_private = try!(JsBuffer::new(scope, kp_private.len() as u32));

    memcpy(&kp_private, &mut jsb_kp_private);

    let mut jsb_kp_public = try!(JsBuffer::new(scope, kp_public.len() as u32));

    memcpy(&kp_public, &mut jsb_kp_public);

    let _ = outobj.set("private", jsb_kp_private);
    let _ = outobj.set("public", jsb_kp_public);

    Ok(outobj)
}

fn exchange(mut call: Call) -> JsResult<JsBuffer> {
    let scope = call.scope;

    let bobPublicKey = try!(call.check_argument::<JsBuffer>(0));
    let alicePrivateKey = try!(call.check_argument::<JsBuffer>(1));

    let mut shared_key = crypto::ed25519::exchange(bobPublicKey.lock().unwrap(), alicePrivateKey);

    let jsb_shared_key = try!(JsBuffer::new(scope, shared_key.len() as u32));

    memcpy(&shared_key, &mut jsb_shared_key);

    let _ = (1..1000).collect::<Vec<i32>>();

    Ok(jsb_shared_key)
}

register_module!(m, {
    try!(m.export("keypair", keypair));
    try!(m.export("exchange", exchange));

    Ok(())
});
