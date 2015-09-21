#!/usr/bin/env node
"use strict";var sslinfo=require("sslinfo");var program=require("commander");var chalk=require("chalk");var pkg=require("../package.json");program.version(pkg.version).option("--host <host>","Hostname or IP address to peek at").option("--port [port]","Port to peek at.  Defaults to 443.").parse(process.argv);if(!program.host){console.log();console.log("  Host is required");program.help();}if(Number.isNaN(Number(program.port))){program.port = 443;}console.log("==================================================");console.log("  Peeking at " + program.host + ":" + program.port);sslinfo.getServerResults({host:program.host,port:program.port}).done(function(results){console.log("--- Certificate ----------------------------------");console.log("  CN: " + results.cert.subject.commonName);console.log("  ON: " + results.cert.subject.organizationName);console.log("  Issuer:");console.log("    CN: " + results.cert.issuer.commonName);console.log("    ON: " + results.cert.issuer.organizationName);console.log("  Valid:");console.log("    After: " + results.cert.notBefore);console.log("    Until: " + results.cert.notAfter);console.log("--- Protocols ------------------------------------");var _iteratorNormalCompletion=true;var _didIteratorError=false;var _iteratorError=undefined;try{for(var _iterator=results.protocols[Symbol.iterator](),_step;!(_iteratorNormalCompletion = (_step = _iterator.next()).done);_iteratorNormalCompletion = true) {var proto=_step.value;console.log("  " + proto.name + " - " + (proto.enabled?chalk.green("ENABLED"):chalk.red("disabled")));}}catch(err) {_didIteratorError = true;_iteratorError = err;}finally {try{if(!_iteratorNormalCompletion && _iterator["return"]){_iterator["return"]();}}finally {if(_didIteratorError){throw _iteratorError;}}}console.log("--- Ciphers --------------------------------------");for(var cipherMethod in results.ciphers) {if(results.ciphers.hasOwnProperty(cipherMethod)){var cipherFamily=results.ciphers[cipherMethod];console.log("  " + cipherFamily.name + " ciphers:");var _iteratorNormalCompletion2=true;var _didIteratorError2=false;var _iteratorError2=undefined;try{for(var _iterator2=cipherFamily.enabled[Symbol.iterator](),_step2;!(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done);_iteratorNormalCompletion2 = true) {var cipher=_step2.value;console.log("    " + cipher);}}catch(err) {_didIteratorError2 = true;_iteratorError2 = err;}finally {try{if(!_iteratorNormalCompletion2 && _iterator2["return"]){_iterator2["return"]();}}finally {if(_didIteratorError2){throw _iteratorError2;}}}}}},function(error){console.log("Error");console.log(error);});