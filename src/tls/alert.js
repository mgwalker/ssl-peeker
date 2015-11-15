module.exports = function(msg) {
	let level = "";
	let message = "";

	switch(msg[5]) {
		case 0x01:
			level = "WARNING";
			break;
		case 0x02:
			level = "FATAL";
			break;
		default:
			level = "UNKNOWN";
			break;
	}

	switch(msg[6]) {
		case 0x00:
			message = "CLOSE NOTIFY";
			break;

		case 0x0a:
			message = "UNEXPECTED MESSAGE";
			break;

		case 0x16:
			message = "RECORD OVERFLOW";
			break;

		case 0x28:
			message = "HANDSHAKE FAILURE";
			break;

		case 0x2f:
			message = "ILLEGAL PARAMETER";
			break;

		case 0x31:
			message = "ACCESS DENIED";
			break;

		case 0x3c:
			message = "EXPORT RESTRICTION";
			break;

		case 0x46:
			message = "PROTOCOL VERSION";
			break;

		case 0x47:
			message = "INSUFFICIENT SECURITY";
			break;

		case 0x50:
			message = "INTERNAL ERROR";
			break;

		default:
			message = "UNKNOWN";
			break;
	}

	return { level, message };
};
