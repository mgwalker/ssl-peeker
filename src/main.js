#!/usr/bin/env node

const sslinfo = require("sslinfo");
const chalk = require("chalk");
const tlsHandshake = require("./tls/tls-handshake");

const ciphers = require("../ciphers.json");
const cipherIDs = [ ];
for(let cipher of ciphers) {
	cipherIDs.push(...cipher.id);
}

function getCipherName(id) {
	for(let cipher of ciphers) {
		if(cipher.id[0] == id[0] && cipher.id[1] == id[1]) {
			return cipher.name;
		}
	}
}

//process.exit(0);
//*/

const host = process.argv[2];

tlsHandshake(host, cipherIDs, "TLSv1.0")
	.then(msg => {
		console.log(`Server supports ${msg.tlsVersion} with cipher suite ${getCipherName(msg.cipherSuite)}`);
	})
	.catch(e => {
		console.error("Error:");
		console.error(e);
	});

/*
if (process.argv.length < 3) {
	console.log();
	console.log("Usage: ssl-peeker <host> [port]");
	console.log();
} else {
	const hostname = process.argv[2];
	let port = Number(process.argv[3]) || 443;

	if (port < 0 || port > 65535) {
		port = 443;
	}

	console.log("==================================================");
	console.log(`  Peeking at ${hostname}:${port}`);

	sslinfo.getServerResults({ host: hostname, port: port })
		.done(function(results) {
			console.log("--- Certificate ----------------------------------");
			console.log(`  CN: ${results.cert.subject.commonName}`);
			console.log(`  ON: ${results.cert.subject.organizationName}`);
			console.log(`  Issuer:`);
			console.log(`    CN: ${results.cert.issuer.commonName}`);
			console.log(`    ON: ${results.cert.issuer.organizationName}`);
			console.log(`  Valid:`);
			console.log(`    After: ${results.cert.notBefore}`);
			console.log(`    Until: ${results.cert.notAfter}`);
			console.log("--- Protocols ------------------------------------");
			for (const proto of results.protocols) {
				console.log(`  ${proto.name} - ${proto.enabled ? chalk.green("ENABLED") : chalk.red(`${proto.error ? chalk.magenta(`unknown - ${proto.error}`) : "disabled"}`)}`);
			}
			console.log("--- Ciphers --------------------------------------");
			for (let cipherMethod in results.ciphers) {
				if (results.ciphers.hasOwnProperty(cipherMethod)) {
					const cipherFamily = results.ciphers[cipherMethod];

					console.log(`  ${cipherFamily.name} ciphers:`);

					for (const cipher of cipherFamily.enabled) {
						console.log(`    ${cipher}`);
					}
				}
			}
		},
		function(error) {
			console.log("Error");
			console.log(error);
		});
}
*/
