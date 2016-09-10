'use strict';

const assert = require('assert');
const arx = require('../native');

class Crypto {
	constructor(arx) {
		assert(arx, 'You must pass an arx instance!');

		this.arx = arx;
	}

	keypair () {
		return this.arx.keypair();
	}
}

module.exports = new Crypto(arx);
module.exports.Crypto = Crypto;
