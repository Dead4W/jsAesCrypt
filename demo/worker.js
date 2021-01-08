let cdnPath = "https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/";
let libPath = "libs/";

self.importScripts(
	cdnPath + "core.min.js",
	cdnPath + "enc-utf16.min.js",
	libPath + "enc-uint8array.min.js",
	libPath + "aes_crypt.min.js",
);

onmessage = function(e) {
	let data = e.data;
	let action = data[0];

	if( action === "ENCRYPT" || action === "DECRYPT" ) {
		let aes = aesCrypt();

		let file = data[1];
		let fileName = data[3];
		let passw = data[2];

		if( action === "ENCRYPT" ) {
				aes.encrypt(file, passw).then((r) => {
					postMessage(["ENCRYPT", r, fileName + ".aes"]);
				});
		} else {
			aes.decrypt(file, passw).then((r) => {
				postMessage(["DECRYPT", r, fileName.split('.').slice(0, -1).join('.')]);
			});
		}
	}

}