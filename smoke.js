'use strict';

const {Ed25519} = require('./lib');
const ed25519 = new Ed25519;

const alice = ed25519.keypair();
const bob = ed25519.keypair();

const exchange = ed25519.exchange(bob.public, alice.private);
const exchange2 = ed25519.exchange(alice.public, bob.private);

console.log('alice public_key', alice.public);
console.log('alice private_key', alice.private);

console.log('');

console.log('bob public_key', bob.public);
console.log('bob private_key', bob.private);

console.log('');
console.log('=========');
console.log('');

console.log('alice shared_key', exchange);
console.log('bob shared_key', exchange2);

console.log('');
console.log('=========');
console.log('');

const alicePlain = "I like cats!";

console.log('alice plain', alicePlain);

const aliceSignature = ed25519.signature(new Buffer(alicePlain), alice.private);

console.log('alice signature', aliceSignature);

console.log('');
console.log('=========');
console.log('');

const bobVerify = ed25519.verify(new Buffer(alicePlain), alice.public, aliceSignature);

console.log('bob verify', bobVerify);