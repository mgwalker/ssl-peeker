#!/usr/bin/env node

const sslinfo = require("sslinfo");
const program = require("commander");
const chalk = require("chalk");
const pkg = require("../package.json");

program
	.version(pkg.version)
	.option("--host <host>", "Hostname or IP address to peek at")
	.option("--port [port]", "Port to peek at.  Defaults to 443.")
.parse(process.argv);

if (!program.host) {
	console.log();
	console.log("  Host is required");
	program.help();
}
if (Number.isNaN(Number(program.port))) {
	program.port = 443;
}

console.log("==================================================");
console.log(`  Peeking at ${program.host}:${program.port}`);

sslinfo.getServerResults({ host: program.host, port: program.port })
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
			console.log(`  ${proto.name} - ${proto.enabled ? chalk.green("ENABLED") : chalk.red("disabled")}`);
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
