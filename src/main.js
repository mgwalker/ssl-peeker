#!/usr/bin/env node

const sslinfo = require("sslinfo");
const chalk = require("chalk");
const tlsHandshake = require("./tls/tls-handshake");
const Queue = require("nbqueue");

const ciphers = require("../ciphers.json");
const cipherIDs = [ ];
for(let cipher of ciphers) {
	cipherIDs.push(...cipher.id);
}

function getCipherName(id) {
	for(let cipher of ciphers) {
		if(cipher.id[0] == id[0] && cipher.id[1] == id[1]) {
			return `${cipher.keyExchange} key exchange with ${cipher.authentication} authentication, using ${cipher.bits}-bit ${cipher.encryption} encryption (${cipher.mac} MAC)`;
		}
	}
}

const host = process.argv[2];
const sslVersions = [
	"SSLv1.0", "SSLv2.0", "SSLv3.0",
	"TLSv1.0", "TLSv1.1", "TLSv1.2"
];

const progress = new (require("progress"))("Testing ciphers [:bar] :current/:total (:percent) :etas", {
	incomplete: "░",
	complete: chalk.green.bold("▓"),
	width: 40,
	total: sslVersions.length * ciphers.length
});

const tlsChecks = { };
function tick(next, sslVersion, cipherID, pass) {
	tlsChecks[sslVersion].push({
		name: getCipherName(cipherID),
		supported: pass
	});

	progress.tick(1);
	setTimeout(next, 300);
}

const queue = new (require("nbqueue"))(25);
const promises = [ ];
for(let sslVersion of sslVersions) {
	tlsChecks[sslVersion] = [ ];
	for(let cipher of ciphers) {
		queue.add(next => {
			promises.push(
				tlsHandshake(host, cipher.id, sslVersion)
					.then(msg => tick(next, sslVersion, cipher.id, true))
					.catch(e => tick(next, sslVersion, cipher.id, false))
			);
		});
	}
}

queue.done(() => {
	Promise.all(promises).then(() => {
		console.log("\n");
		for(let sslVersion of Object.keys(tlsChecks)) {
			const supportedCiphers = tlsChecks[sslVersion].filter(cipher => cipher.supported);
			console.log(sslVersion);
			console.log("--------------------");

			if(supportedCiphers.length > 0) {
				for(let cipher of supportedCiphers.sort((a, b) => a < b)) {
					console.log(`   ${chalk.green("✓")} ${cipher.name}`);
				}
			} else {
				console.log(`   ${chalk.red("✗")} no supported ciphers`);
			}
			console.log("\n");
		}
	}).catch(e => console.log(e));
});
