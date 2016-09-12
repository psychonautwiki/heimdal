extern crate neon;
use neon::vm::{Lock, This, FunctionCall, JsResult};
use neon::mem::Handle;
use neon::js::binary::JsBuffer;
use neon::js::Value;

// fn my_helper_function<'a, S: Scope<'a>>(scope: &'a mut S, obj: Handle<'a, JsObject>) -> JsResult<'a, JsValue> {
// ...
// }
//

pub trait CheckArgument<'a> {
    fn check_argument<V: Value>(&mut self, i: i32) -> JsResult<'a, V>;
}

impl<'a, T: This> CheckArgument<'a> for FunctionCall<'a, T> {
    fn check_argument<V: Value>(&mut self, i: i32) -> JsResult<'a, V> {
        try!(self.arguments.require(self.scope, i)).check::<V>()
    }
}

#[macro_export]
macro_rules! assert_buf_with_size {
    ($scope:expr, $slice:expr, $name:expr, $len:expr) => {{
        if !($slice.len() == $len) {
            let err = try!(JsError::new(
                $scope,
                Kind::RangeError,
                concat!("Expected '", $name, "' to have length ", $len)
            ));

            return throw(err);
        }
    }};
}

pub fn buf_copy_from_slice(data: &[u8], buf: &mut Handle<JsBuffer>) {
    buf.grab(|mut contents| {
        let slice = contents.as_mut_slice();

        slice.copy_from_slice(data);
    });
}

pub fn buf_to_vec(mut inbuf: Handle<JsBuffer>) -> Vec<u8> {
    let outobj = inbuf.grab(|contents| contents.as_slice().to_vec());

    outobj
}
