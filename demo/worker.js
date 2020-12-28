let base_cdn = "https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/";
let base_libs = "libs/";

self.importScripts(
	base_cdn + "core.min.js",
	base_cdn + "cipher-core.min.js",
	base_cdn + "aes.min.js",
	base_cdn + "hmac.min.js",
	base_cdn + "sha256.min.js",
	base_cdn + "pad-nopadding.min.js",
	base_cdn + "enc-utf16.min.js",
	base_libs + "enc-uint8array.min.js",
	base_libs + "aes_crypt.min.js",
);

let last_progress = 0;

function callback_progress(c) {
	let progress = Math.floor(c*100);
	if( last_progress === progress ) return;

	postMessage(["PROGRESS", last_progress = progress]);
}

onmessage = function(e) {
	let data = e.data;
	let action = data[0];

	if( action === "ENCRYPT" || action === "DECRYPT" ) {
		let aes = AesCrypt();

		let file = data[1];
		let file_name = data[3];
		let passw = data[2];

		if( action === "ENCRYPT" ) {
				aes.encrypt(file, passw, callback_progress).then((r) => {
					postMessage(["ENCRYPT", r, file_name + ".aes"]);
				});
		} else {
			aes.decrypt(file, passw, callback_progress).then((r) => {
				postMessage(["DECRYPT", r, file_name.split('.').slice(0, -1).join('.')]);
			});
		}
	}

}