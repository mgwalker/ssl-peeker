"use strict";var net=require("net");var tlsVersions=[{simple:"1.0",name:"TLSv1.0",versionID:[0x03,0x01]},{simple:"1.1",name:"TLSv1.1",versionID:[0x03,0x02]},{simple:"1.2",name:"TLSv1.2",versionID:[0x03,0x03]}];function numberInByteArray(number,bytes){var byteArray=[];for(var byteOffset=bytes - 1;byteOffset >= 0;byteOffset--) {byteArray.push(number >> byteOffset * 8 & 0xff);}return byteArray;}function wrapTLSRecord(messageType,tlsVersion,buffer){return Buffer.concat([new Buffer([messageType].concat(tlsVersion).concat(numberInByteArray(buffer.length,2))),buffer]);}module.exports = function tlsHandshake(host){var cipherSuites=arguments.length <= 1 || arguments[1] === undefined?[]:arguments[1];var tlsVersion=arguments.length <= 2 || arguments[2] === undefined?"1.2":arguments[2];var port=arguments.length <= 3 || arguments[3] === undefined?443:arguments[3];return new Promise(function(resolve,reject){if(typeof host !== "string"){throw new Error("host is required");}else if(Number.isNaN(Number(port)) || Number(port) < 0 || Number(port) > 65535){throw new Error("port " + port + " is invalid: must be a number between 0 and 65535");}else if(!tlsVersions.some(function(v){return v.simple === tlsVersion;})){throw new Error("invalid TLS version: " + tlsVersion);}else if(!Array.isArray(cipherSuites) || cipherSuites.some(function(c){return Number.isNaN(Number(c) || c < 0 || c > 255);})){throw new Error("cipher suites must be an array of 8-bit unsigned numbers");}else if(cipherSuites.length % 2 !== 0){throw new Error("cipher suites must be pairs of 8-bit unsigned numbers");}else if(cipherSuites.length < 2 || cipherSuites.length > 131072){throw new Error(cipherSuites.length / 2 + " cipher suites specified; must be between 1 and 65536");}var tlsVersionInfo=undefined;tlsVersions.some(function(v){tlsVersionInfo = v;return v.simple === tlsVersion;});var randomBytes=numberInByteArray(Math.round(Date.now() / 1000),4);for(var i=0;i < 28;i++) {randomBytes.push(Math.round(Math.random() * 256));}var clientHelloData=tlsVersionInfo.versionID.concat(randomBytes).concat([0x00]).concat(numberInByteArray(cipherSuites.length,2)).concat(cipherSuites).concat([0x01,0x00,0x00,0x00]);var clientHelloHeader=[0x01].concat(numberInByteArray(clientHelloData.length,3));var tlsSocket=net.createConnection({host:host,port:port},function(){console.log("Connected to " + host + ":" + port);tlsSocket.write(wrapTLSRecord(0x16,tlsVersionInfo.versionID,new Buffer(clientHelloHeader.concat(clientHelloData))));console.log(wrapTLSRecord(0x16,tlsVersionInfo.versionID,new Buffer(clientHelloHeader.concat(clientHelloData))));});tlsSocket.on("data",function(data){switch(data[0]){case 0x15:console.log("ALERT MESSAGE");switch(data[5]){case 0x01:console.log("WARNING");break;case 0x02:console.log("FATAL");break;default:console.log("UNKNOWN");break;}switch(data[6]){case 0x00:console.log(" --> CLOSE NOTIFY");break;case 0x0a:console.log(" --> UNEXPECTED MESSAGE");break;case 0x16:console.log(" --> RECORD OVERFLOW");break;case 0x28:console.log(" --> HANDSHAKE FAILURE");break;case 0x2f:console.log(" --> ILLEGAL PARAMETER");break;case 0x31:console.log(" --> ACCESS DENIED");break;case 0x3c:console.log(" --> EXPORT RESTRICTION");break;case 0x46:console.log(" --> PROTOCOL VERSION");break;case 0x47:console.log(" --> INSUFFICIENT SECURITY");break;case 0x50:console.log(" --> INTERNAL ERROR");break;default:console.log(" --> UNKNOWN");break;}break;}console.log("Got some stuff back from the server:");console.log(data);tlsSocket.end();});tlsSocket.on("end",function(){console.log("TLS socket closed");});setTimeout(resolve,750);});};