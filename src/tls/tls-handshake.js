const net = require("net");

const tlsVersions = [
	{
		name: "SSLv1.0",
		versionID: [ 0x01, 0x00 ]
	},
	{
		name: "SSLv2.0",
		versionID: [ 0x02, 0x00 ]
	},
	{
		name: "SSLv3.0",
		versionID: [ 0x03, 0x00 ]
	},
	{
		simple: "1.0",
		name: "TLSv1.0",
		versionID: [ 0x03, 0x01 ]
	},
	{
		simple: "1.1",
		name: "TLSv1.1",
		versionID: [ 0x03, 0x02 ]
	},
	{
		simple: "1.2",
		name: "TLSv1.2",
		versionID: [ 0x03, 0x03 ]
	}];

function numberInByteArray(number, bytes) {
	let byteArray = [ ];
	for(let byteOffset = bytes - 1; byteOffset >= 0; byteOffset--) {
		byteArray.push((number >> (byteOffset * 8)) & 0xff);
	}
	return byteArray;
}

function wrapTLSRecord(messageType, tlsVersion, buffer) {
	return Buffer.concat([ new Buffer([ messageType ].concat(tlsVersion).concat(numberInByteArray(buffer.length, 2))), buffer ]);
}

module.exports = function tlsHandshake(host, cipherSuites = [ ], tlsVersion = "TLSv1.2", port = 443) {
	return new Promise((resolve, reject) => {
		if(typeof host !== "string") {
			throw new Error("host is required");
		} else if(Number.isNaN(Number(port)) || Number(port) < 0 || Number(port) > 65535) {
			throw new Error(`port ${port} is invalid: must be a number between 0 and 65535`);
		} else if(!tlsVersions.some(v => v.name === tlsVersion)) {
			throw new Error(`invalid TLS version: ${tlsVersion}`);
		} else if(!Array.isArray(cipherSuites) || cipherSuites.some(c => Number.isNaN(Number(c) || c < 0 || c > 255))) {
			throw new Error("cipher suites must be an array of 8-bit unsigned numbers");
		} else if(cipherSuites.length % 2 !== 0) {
			throw new Error("cipher suites must be pairs of 8-bit unsigned numbers");
		} else if(cipherSuites.length < 2 || cipherSuites.length > 131072) {
			throw new Error(`${cipherSuites.length/2} cipher suites specified; must be between 1 and 65536`);
		}

		let tlsVersionInfo;
		tlsVersions.some(v => {
			tlsVersionInfo = v;
			return v.name === tlsVersion;
		});

		// The random bits start with a 4-byte epoch timestamp. The final
		// 28 bytes are random.  Since we're not actually trying to make
		// a secure connection, we don't have to commit to high-quality
		// cryptographic randomness.
		const randomBytes = numberInByteArray(Math.round(Date.now() / 1000), 4);
		for(var i = 0; i < 28; i++) {
			randomBytes.push(Math.round(Math.random() * 256));
		}

		const clientHelloData = tlsVersionInfo.versionID
			.concat(randomBytes)
			.concat([ 0x00 ])
			.concat(numberInByteArray(cipherSuites.length, 2))
			.concat(cipherSuites)
			.concat([ 0x01, 0x00, 0x00, 0x00 ]);
		const clientHelloHeader = [ 0x01 ].concat(numberInByteArray(clientHelloData.length, 3));

		const tlsSocket = net.createConnection({ host: host, port: port }, () => {
			tlsSocket.write(wrapTLSRecord(0x16, tlsVersionInfo.versionID, new Buffer(clientHelloHeader.concat(clientHelloData))));
		});

		let inServerHello = false;
		tlsSocket.on("data", data => {
			//console.log("FROM SERVER:")
			//console.log(data);
			//console.log("---");

			switch((inServerHello === true) ? 0x16 : data[0]) {
				case 0x15:
					reject(require("./alert")(data));
					tlsSocket.end();
					break;
				case 0x16:
					switch((inServerHello === true) ? 0x02 : data[5]) {
						case 0x02 || inServerHello:
							inServerHello = require("./server-hello")(data);
							if(inServerHello !== true) {
								inServerHello.then(msg => {
									resolve(msg);
									tlsSocket.end();
								});
							}
							break;
					}
					break;
			}
			tlsSocket.end();
		});
		tlsSocket.on("error", (...stuff) => { });
		tlsSocket.on("end", () => reject("Connection closed without resolution"));
	});
}
