'use strict';

const {assert, expect} = require('chai');

const {Ed25519} = require('../lib');

const assertThrow = fn => expect(fn).to.throw;

describe('ed25519', () => {
	let ed25519;

	beforeEach(() => {
		ed25519 = new Ed25519;
	});

	describe('keypair', () => {
		let keypair;

		beforeEach(() => {
			keypair = ed25519.keypair();
		});

		it ('should return a 32 byte slice and a 64 byte slice', () => {
			assert(32 === keypair.public.length);
			assert(64 === keypair.private.length);
		});
	});

	describe('exchange', () => {
		let alice;
		let bob;

		beforeEach(() => {
			alice = ed25519.keypair();
			bob = ed25519.keypair();
		});

		describe('unit', () => {
			it ('should not accept bad public key', () => {
				assertThrow(() => ed25519.exchange(null, new Buffer(64)));
				assertThrow(() => ed25519.exchange(new Buffer(24), new Buffer(64)));
			});

			it ('should not accept bad private key', () => {
				assertThrow(() => ed25519.exchange(new Buffer(32), null));
				assertThrow(() => ed25519.exchange(new Buffer(32), new Buffer(43)));
			});
		});

		describe('shared key (from keypair)', () => {
			/* bobPuK + alicePrK */
			let aliceSharedKey;

			/* alicePuK + bobPrK */
			let bobSharedKey;

			beforeEach(() => {
				aliceSharedKey = ed25519.exchange(bob.public, alice.private);
				bobSharedKey = ed25519.exchange(alice.public, bob.private);
			});

			it ('should obtain two identical shared keys', () =>
				assert(0 === Buffer.compare(aliceSharedKey, bobSharedKey))
			);
		});

		describe('shared key (random test vectors)', () => {
			[
				[
					'936f256625657e532264b8c3de947be2b36b120bea69c7957e35f7d297697537' +
					'e2ae56b85e1467abde23a812065e7d3b7a6fe65112add65fbae3217079e43ef0',

					'e2ae56b85e1467abde23a812065e7d3b7a6fe65112add65fbae3217079e43ef0',

					'dc42d81255900518a8048303179ea9dde9cfbffdf0029479bd3eb3075ad4bdaa' +
					'fdc341a6f89e7a7b0416050b67302dcff3101211ce3ccf8e4d63cfa030b10e12',

					'fdc341a6f89e7a7b0416050b67302dcff3101211ce3ccf8e4d63cfa030b10e12',

					'031734af210395d8a0eb9f003fcf54582f5f171b75e70d582cbc2b05b1441419'
				],

				[
					'610ccb8d21c39c9ae461595ca41477646d9685d1e8d27b4c0c720ca849208446' +
					'96d4ad2e963b0b9ecc9dc38b63796667ad1709e06ebbaccc75297f6dfc16f2cc',

					'96d4ad2e963b0b9ecc9dc38b63796667ad1709e06ebbaccc75297f6dfc16f2cc',

					'b080300a91eadabe8f5c504959ecec9e74e51dc5d301791b8d9f39cbdf7434c7' +
					'714c9c78d868fa060a2da17da226c65f6d30431ad05c6419ea0cf0bc2d6129e8',

					'714c9c78d868fa060a2da17da226c65f6d30431ad05c6419ea0cf0bc2d6129e8',

					'5f5a3c6c9738761276638b74921adb071cab475405692d7a599669c7ad402278'
				],

				[
					'5cd409ba1a1d796f06977202a373aa6e235846b621da313bc0692a8aae77ee68' +
					'9c7df4ae8a12b9a2c918466e751de3e8dd026409172083152eeaa0c174b97eb1',

					'9c7df4ae8a12b9a2c918466e751de3e8dd026409172083152eeaa0c174b97eb1',

					'07be4e0e70bb75fe67551ee53641d7370b7a54e8bf42aacd9279561f370c6a9a' +
					'56cd289825c296649694532cf1abadce6cc214995624be97370579c301cdf02c',

					'56cd289825c296649694532cf1abadce6cc214995624be97370579c301cdf02c',

					'dd449d853114cf1fa4915fb0dcb877e638d5f242c1314538b9025fa1e4245d4b'
				],
				[
					'dd34381084052e9c09ba3139d53b1c6fe862185b8f9f7e1ecacb56230959ccab' +
					'0f00016bb3afb4379a018350a3405638ffad96beb957ab928198cc96c3fee20c',

					'0f00016bb3afb4379a018350a3405638ffad96beb957ab928198cc96c3fee20c',

					'2d189187a057de8a47e19469e3b97ab285bb07d9cd52fba53c69ea81d56ee462' +
					'bdb2ad39636e5b06aa581de43584060c8ad2c17bc27e1a92dec98f26822e5f9f',

					'bdb2ad39636e5b06aa581de43584060c8ad2c17bc27e1a92dec98f26822e5f9f',

					'29ebf47c483f70d5fcb0b471b277ec121cf89945c72790974ed5f38c81265032'
				]
			].map(testVector =>
				testVector.map(vec =>
					new Buffer(vec, 'hex')
				)
			).forEach(([alicePrK, alicePuK, bobPrK, bobPuK, sharedKey], i) => {
				it (`Test vector ${i} passed`, () => {
					const aliceShK = ed25519.exchange(bobPuK, alicePrK);
					const bobShK = ed25519.exchange(alicePuK, bobPrK);

					assert(
						0 === Buffer.compare(aliceShK, bobShK),
						`${aliceShK.toString('hex')} != ${bobShK.toString('hex')}`
					);
				});
			});
		});

		describe('signature (from test vector)', () => {
			[
				[
					'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60' +
					'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',

					'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',

					'',

					'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
					'5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
				],
				[
					'4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb' +
					'3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',

					'3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',

					'72',

					'92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' +
					'085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'
				],
				[
					'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7' +
					'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',

					'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',

					'af82',

					'6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac' +
					'18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'
				],
				[
					'b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd' +
					'77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb',

					'77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb',

					'916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171' +
					'ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01' +
					'dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313' +
					'c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460' +
					'376d7f3ac22ff372c18f613f2ae2e856af40',

					'6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b' +
					'4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509'
				],
				[
					'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5' +
					'278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',

					'278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',

					'08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98' +
					'fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8' +
					'79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d' +
					'658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc' +
					'1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe' +
					'ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e' +
					'06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef' +
					'efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7' +
					'aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1' +
					'85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2' +
					'd17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24' +
					'554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270' +
					'88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc' +
					'2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07' +
					'07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba' +
					'b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a' +
					'ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e' +
					'c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7' +
					'51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c' +
					'42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8' +
					'ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df' +
					'f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08' +
					'd78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649' +
					'de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4' +
					'88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3' +
					'2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e' +
					'6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f' +
					'b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5' +
					'0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1' +
					'369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d' +
					'b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c' +
					'0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0',

					'0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350' +
					'aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03'
				]
			].map(testVector =>
				testVector.map(vec =>
					new Buffer(vec, 'hex')
				)
			).forEach(([tv_privateKey, tv_publicKey, tv_message, tv_signature], i) => {
				it (`Test vector ${i} passed (${tv_message.length} bytes)`, () => {
					const signature = ed25519.signature(tv_message, tv_privateKey);

					assert(
						0 === Buffer.compare(tv_signature, signature),
						`${tv_signature.toString('hex')} != ${signature.toString('hex')}`
					);
				});
			});
		});
	});
});