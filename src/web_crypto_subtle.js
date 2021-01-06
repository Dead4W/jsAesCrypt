/** global: webCryptSubtle */

const webCryptSubtle = {

    _createKey: async function(intKeyArr, mode, functions) {
        return await crypto.subtle.importKey( "raw", intKeyArr.buffer,   mode ,  false,   functions);
    },

    _webHashHMAC: async function(text, intKeyArr) {
        let key_encoded = await this._createKey(
            intKeyArr,
            { // algorithm details
                name: "HMAC",
                hash: {name: "SHA-256"}
            },
            ["sign", "verify"],
            );

        return new Uint8Array( await crypto.subtle.sign(
            "HMAC",
            key_encoded,
            text
        ) );
    },

    _webEncryptAes :async function(pText, intKeyArr, iv0, stayLast=true) {
        let key_encoded = await this._createKey(intKeyArr, "AES-CBC", ["encrypt", "decrypt"]);

        let encrypted = new Uint8Array( await crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: iv0,
            },
            key_encoded,
            pText
        ) );

        if( pText.length % this.info.AESBlockSize === 0 && stayLast == true ) {
            encrypted = encrypted.slice(0, encrypted.length - this.info.AESBlockSize);
        }

        return encrypted;
    },

    _webHashSHA256: async function(text) {
        return new Uint8Array(await crypto.subtle.digest("SHA-256", text.buffer));
    },

    _webDecryptAes: async function(cText, intKeyArr, iv0, fs16 = 0) {
        let key_encoded = await this._createKey(intKeyArr, "AES-CBC", ["encrypt", "decrypt"]);
        let cTextArr = binaryStream(cText);

        // dirty cheat to add encrypted block pkcs7 padding if mod = 0
        // because WebCrypto subtle working only with pkcs7 pad
        if( fs16 == 0 ) {
            let modBlock = new Uint8Array(this.info.AESBlockSize);

            // xor padding with last block (see mode AES-CBC)
            for( let i = 0; i < this.info.AESBlockSize;i++ ) {
                modBlock[i] = 0x00 ^ cText[cText.length - this.info.AESBlockSize + i];
            }

            modBlockEncrypted = await this._webEncryptAes(modBlock, intKeyArr, iv0, false);

            cTextArr.appendBytes(modBlockEncrypted);
        }

        let pText = new Uint8Array( await crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: iv0,
            },
            key_encoded,
            cTextArr.finalize()
        ) );

        // clear empty data pkcs7 padding block
        if( fs16 == 0 ) {
            pText = pText.slice(0, pText.length - this.info.AESBlockSize);
        }

        return pText;
    },
}