# Heimdal

Safe, yet incredibly fast cryptography for Node powered by the safe systems language [Rust](https://www.rust-lang.org), the Rust-bridge framework [Neon](http://neon.rustbridge.io/) and the pure-Rust cryptography library [rust-crypto](https://github.com/DaGenix/rust-crypto).

> I know you loved him. I tried to tell him so, but he wouldn’t listen. So cruel to put the hammer within your reach, knowing that you could never lift it. The burden of the throne has fallen to me now.

### What is heimdal?

heimdal builds on [Neon](http://neon.rustbridge.io/), a Rust-Node bridge and [rust-crypto](https://github.com/DaGenix/rust-crypto), a safe, pure-Rust cryptography library. The goal is to provide safety and performance to developers while maintaining a high level of usability on all supported architectures.

#### Architecture

1. Heimdal consists of only three direct components - a PRNG as entropy source, the business logic and Neon for integration with Node.
2. Rust builds an object file from heimdal and links it to the Node-ABI-specific V8 abstraction layer provided by Neon, finally producing a native Node module.
3. Upon build, the test-suite is executed against the binary, verifying the integrity of the crypto functions and mitigating potential issues caused by unsafe compiler optimisations.

#### Installation

If you're reading this, heimdal may be still too raw for you. However, if you have a nightly Rust toolchain installed, just run `npm i`. This will kickoff the build and test suite.

#### Usage

```
'use strict';

const heimdal = require('heimdal');
```

### Example usage for Ed25519

```
'use strict';

const assert = require('assert');

const heimdal = require('heimdal');
const ed25519 = new heimdal.Ed25519();

const alice = ed25519.keypair();
const bob = ed25519.keypair();

const aliceSharedSecret = ed25519.exchange(alice.public, bob.private);
const bobSharedSecret = ed25519.exchange(bob.public, alice.private);

assert(0 === Buffer.compare(aliceSharedSecret, bobSharedSecret));

const message = new Buffer([
	0x49, 0x74, 0x27, 0x73, 0x20, 0x61, 0x62,
	0x6f, 0x75, 0x74, 0x20, 0x68, 0x6f, 0x77,
	0x20, 0x68, 0x61, 0x72, 0x64, 0x20, 0x79,
	0x6f, 0x75, 0x20, 0x63, 0x61, 0x6e, 0x20,
	0x67, 0x65, 0x74, 0x20, 0x68, 0x69, 0x74,
	0x20, 0x61, 0x6e, 0x64, 0x20, 0x6b, 0x65,
	0x65, 0x70, 0x20, 0x6d, 0x6f, 0x76, 0x69,
	0x6e, 0x67, 0x20, 0x66, 0x6f, 0x72, 0x77,
	0x61, 0x72, 0x64, 0x3b, 0x0a, 0x68, 0x6f,
	0x77, 0x20, 0x6d, 0x75, 0x63, 0x68, 0x20,
	0x79, 0x6f, 0x75, 0x20, 0x63, 0x61, 0x6e,
	0x20, 0x74, 0x61, 0x6b, 0x65, 0x20, 0x61,
	0x6e, 0x64, 0x20, 0x6b, 0x65, 0x65, 0x70,
	0x20, 0x6d, 0x6f, 0x76, 0x69, 0x6e, 0x67,
	0x20, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72,
	0x64, 0x2e, 0x0a, 0x54, 0x68, 0x61, 0x74,
	0x27, 0x73, 0x20, 0x68, 0x6f, 0x77, 0x20,
	0x77, 0x69, 0x6e, 0x6e, 0x69, 0x6e, 0x67,
	0x20, 0x69, 0x73, 0x20, 0x64, 0x6f, 0x6e,
	0x65, 0x21
]);

console.log('Message:\n\n%s\n', message.toString());

const aliceSignature = ed25519.signature(message, alice.private);

console.log('Alice signature: ', aliceSignature);

const bobVerification = ed25519.verify(message, alice.public, aliceSignature);

console.log('Bob verification: %s', bobVerification);
```

### License

MIT License

Copyright (c) 2017 [Kenan Sulayman](https://sly.mn)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
