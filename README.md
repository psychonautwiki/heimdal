# Heimdallur

Safe, yet incredibly fast cryptography for Node powered by the safe systems language [Rust](https://www.rust-lang.org), the Rust-bridge framework [Neon](http://neon.rustbridge.io/) and the pure-Rust cryptography library [rust-crypto](https://github.com/DaGenix/rust-crypto).

> Be warned, I shall uphold my sacred oath to protect this realm as its gatekeeper. If your return threatens the safety of Ásgarðr, my gate will remain shut and you will be left to perish on the cold waste of Jötunheimr.

### What is heimdal?

heimdal builds on [Neon](http://neon.rustbridge.io/), a Rust-Node bridge and [rust-crypto](https://github.com/DaGenix/rust-crypto), a safe, pure-Rust cryptography library. The goal is to provide safety and performance to developers while maintaining a high level of usability on all supported architectures.

#### Architecture

<svg width="463pt" height="448" viewBox="0.00 0.00 463.00 336.00" xmlns="http://www.w3.org/2000/svg"><g class="graph" transform="translate(4 332)"><title>dependencies</title><path fill="#fff" d="M-4 4v-336h463V4H-4z"/><g class="node"><title>N0</title><path fill="none" stroke="#000" d="M209.381-304.438L259-292l49.619-12.438-.046-20.124h-99.146l-.046 20.124z"/><text text-anchor="middle" x="259" y="-306.3" font-family="Times,serif" font-size="14">heimdal</text></g><g class="node"><title>N1</title><path fill="none" stroke="#000" d="M61-219.5v-36h54v36H61z"/><text text-anchor="middle" x="88" y="-233.8" font-family="Times,serif" font-size="14">neon</text></g><g class="edge"><title>N0-&gt;N1</title><path fill="none" stroke="#000" d="M233.029-298.293l-108.337 44.666"/><path stroke="#000" d="M125.644-250.234l-10.58.576 7.912-7.048 2.668 6.472z"/></g><g class="node"><title>N2</title><path fill="none" stroke="#000" d="M401-146.5v-36h54v36h-54z"/><text text-anchor="middle" x="428" y="-160.8" font-family="Times,serif" font-size="14">rand</text></g><g class="edge"><title>N0-&gt;N2</title><path fill="none" stroke="#000" d="M274.596-295.757L400.1-189.19"/><path stroke="#000" d="M402.425-191.807l5.358 9.14-9.889-3.805 4.531-5.335z"/></g><g class="node"><title>N3</title><path fill="none" stroke="#000" d="M220-219.5v-36h78v36h-78z"/><text text-anchor="middle" x="259" y="-233.8" font-family="Times,serif" font-size="14">rust-crypto</text></g><g class="edge"><title>N0-&gt;N3</title><path fill="none" stroke="#000" d="M259-291.934v25.874"/><path stroke="#000" d="M262.5-265.899l-3.5 10-3.5-10h7z"/></g><g class="node"><title>N4</title><path fill="none" stroke="#000" d="M0-73.5v-36h54v36H0z"/><text text-anchor="middle" x="27" y="-87.8" font-family="Times,serif" font-size="14">cslice</text></g><g class="edge"><title>N1-&gt;N4</title><path fill="none" stroke="#000" d="M70.95-219.082C62.235-209.238 52.188-196.271 46-183c-9.357 20.07-14.146 44.784-16.574 63.312"/><path stroke="#000" d="M32.882-119.105l-4.63 9.53-2.323-10.337 6.953.807z"/></g><g class="node"><title>N10</title><path fill="none" stroke="#000" d="M55-146.5v-36h66v36H55z"/><text text-anchor="middle" x="88" y="-160.8" font-family="Times,serif" font-size="14">neon-sys</text></g><g class="edge"><title>N1-&gt;N10</title><path fill="none" stroke="#000" d="M88-219.313v26.744"/><path stroke="#000" d="M91.5-192.529l-3.5 10-3.5-10h7z"/></g><g class="node"><title>N9</title><path fill="none" stroke="#000" d="M288-73.5v-36h54v36h-54z"/><text text-anchor="middle" x="315" y="-87.8" font-family="Times,serif" font-size="14">libc</text></g><g class="edge"><title>N2-&gt;N9</title><path fill="none" stroke="#000" d="M400.934-146.494l-50.005 31.419"/><path stroke="#000" d="M352.567-111.97l-10.33 2.356 6.605-8.283 3.725 5.927z"/></g><g class="edge"><title>N3-&gt;N2</title><path fill="none" stroke="#000" d="M298.23-221.275C324.615-210.87 360.091-196.56 391-183l.293.129"/><path stroke="#000" d="M392.925-185.975l7.675 7.304-10.554-.923 2.879-6.381z"/></g><g class="node"><title>N5</title><path fill="none" stroke="#000" d="M72-73.5v-36h54v36H72z"/><text text-anchor="middle" x="99" y="-87.8" font-family="Times,serif" font-size="14">gcc</text></g><g class="edge"><title>N3-&gt;N5</title><path fill="none" stroke="#000" d="M222.729-219.365C205.128-210.047 184.318-197.469 168-183c-21.312 18.898-40.503 45.213-53.203 64.597"/><path stroke="#000" d="M117.61-116.305l-8.341 6.533 2.446-10.308 5.895 3.775z"/></g><g class="edge"><title>N3-&gt;N9</title><path fill="none" stroke="#000" d="M260.569-219.208c2.16 18.681 7.033 49.019 17.431 73.208 4.215 9.804 10.36 19.661 16.435 28.194"/><path stroke="#000" d="M297.257-119.877l3.157 10.113-8.775-5.937 5.618-4.176z"/></g><g class="node"><title>N11</title><path fill="none" stroke="#000" d="M287.5-146.5v-36h95v36h-95z"/><text text-anchor="middle" x="335" y="-160.8" font-family="Times,serif" font-size="14">rustc-serialize</text></g><g class="edge"><title>N3-&gt;N11</title><path fill="none" stroke="#000" d="M277.397-219.313l32.035 29.927"/><path stroke="#000" d="M311.854-191.913l4.918 9.384-9.697-4.269 4.779-5.115z"/></g><g class="node"><title>N12</title><path fill="none" stroke="#000" d="M177-146.5v-36h54v36h-54z"/><text text-anchor="middle" x="204" y="-160.8" font-family="Times,serif" font-size="14">time</text></g><g class="edge"><title>N3-&gt;N12</title><path fill="none" stroke="#000" d="M245.686-219.313l-22.293 28.779"/><path stroke="#000" d="M226.082-188.291l-8.891 5.762 3.357-10.049 5.534 4.287z"/></g><g class="node"><title>N6</title><path fill="none" stroke="#000" d="M144-73.5v-36h88v36h-88z"/><text text-anchor="middle" x="188" y="-87.8" font-family="Times,serif" font-size="14">kernel32-sys</text></g><g class="node"><title>N7</title><path fill="none" stroke="#000" d="M232.5-.5v-36h55v36h-55z"/><text text-anchor="middle" x="260" y="-14.8" font-family="Times,serif" font-size="14">winapi</text></g><g class="edge"><title>N6-&gt;N7</title><path fill="none" stroke="#000" d="M205.429-73.313l30.059 29.641"/><path stroke="#000" d="M238.068-46.042l4.663 9.513-9.578-4.53 4.915-4.983z"/></g><g class="node"><title>N8</title><path fill="none" stroke="#000" d="M126-.5v-36h88v36h-88z"/><text text-anchor="middle" x="170" y="-14.8" font-family="Times,serif" font-size="14">winapi-build</text></g><g class="edge"><title>N6-&gt;N8</title><path fill="none" stroke="#000" d="M183.643-73.313l-6.855 27.036"/><path stroke="#000" d="M180.167-45.362l-5.85 8.833-.935-10.553 6.785 1.72z"/></g><g class="edge"><title>N10-&gt;N4</title><path fill="none" stroke="#000" d="M73.234-146.313L48.26-117.246"/><path stroke="#000" d="M50.802-114.833l-9.172 5.304 3.862-9.866 5.31 4.562z"/></g><g class="edge"><title>N10-&gt;N5</title><path fill="none" stroke="#000" d="M90.663-146.313l4.143 26.744"/><path stroke="#000" d="M98.29-119.947l-1.928 10.418-4.99-9.346 6.917-1.072z"/></g><g class="edge"><title>N12-&gt;N6</title><path fill="none" stroke="#000" d="M200.127-146.313l-6.027 26.744"/><path stroke="#000" d="M197.45-118.515l-5.613 8.986-1.215-10.525 6.828 1.539z"/></g><g class="edge"><title>N12-&gt;N7</title><path fill="none" stroke="#000" d="M218.586-146.236C226.329-136.237 235.38-123.073 241-110c8.692 20.22 13.524 44.738 16.137 63.151"/><path stroke="#000" d="M260.626-47.157l-2.195 10.365-4.748-9.47 6.943-.895z"/></g><g class="edge"><title>N12-&gt;N9</title><path fill="none" stroke="#000" d="M230.587-146.494l49.12 31.419"/><path stroke="#000" d="M281.707-117.95l6.538 8.336-10.31-2.44 3.772-5.896z"/></g></g></svg>

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

const heimdal = require('./');
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

Do whatever you like. Display my name if you do good, don't use my name if you fuck up. I'm not responsible for wide-spread data corruption and crying managers.

[Kenan Sulayman](https://sly.mn)