let awaitingBytes = false;
let buffer = new Buffer([]);

function checkBufferLength() {
	let length = (buffer[3] << 8) + (buffer[4]);

	// The actual length of data will include the handshake
	// type, TLS version, and length fields, which together
	// make up five bytes.  Need to account for them!
	return buffer.length <= (length + 5);
}

function processMessage() {
	return new Promise(resolve => {
		let tlsVersion = `${buffer[9]}.${buffer[10]}`;
		const sessionIDLength = buffer[43];
		const cipherSuites = `${buffer[43 + sessionIDLength + 1]} ${buffer[43 + sessionIDLength + 2]}`

		switch(tlsVersion) {
			case "3.3":
				tlsVersion = "TLS 1.2";
				break;

			case "3.2":
				tlsVersion = "TLS 1.1";
				break;

			case "3.1":
				tlsVersion = "TLS 1.0";
				break;

			case "3.0":
				tlsVersion = "SSl 3.0";
				break;

			case "2.0":
				tlsVersion = "SSL 2.0";
				break;

			case "1.0":
				tlsVersion = "SSL 1.0";
				break;

			default:
				tlsVersion = `Unkonwn version: ${tlsVersion}`;
				break;
		}

		resolve({
			tlsVersion,
			cipherSuite: [ buffer[43 + sessionIDLength + 1], buffer[43 + sessionIDLength + 2] ]
		});

		awaitingBytes = false;
		buffer = new Buffer([]);
	});
}

module.exports = function(data) {
	if(!awaitingBytes) {
		buffer = data;
	} else {
		buffer = Buffer.concat([buffer, data]);
	}

	awaitingBytes = checkBufferLength();
	if(!awaitingBytes) {
		return processMessage();
	}

	return awaitingBytes;
};
