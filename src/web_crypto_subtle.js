/** global: webCryptSubtle */

const webCryptSubtle = {

    async createKey(intKeyArr, mode, functions) {
        return await crypto.subtle.importKey( "raw", intKeyArr.buffer,   mode ,  false,   functions);
    },

    async webHashHMAC(text, intKeyArr) {
        let key = await this.createKey(
            intKeyArr,
            { // algorithm details
                name: "HMAC",
                hash: {name: "SHA-256"}
            },
            ["sign", "verify"],
            );

        return new Uint8Array( await crypto.subtle.sign(
            "HMAC",
            key,
            text
        ) );
    },

    async webEncryptAes(pText, intKeyArr, iv0, stayLast=true) {
        let key = await this.createKey(intKeyArr, "AES-CBC", ["encrypt", "decrypt"]);

        let encrypted = new Uint8Array( await crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: iv0,
            },
            key,
            pText
        ) );

        if( pText.length % this.info.AESBlockSize === 0 && stayLast === true ) {
            encrypted = encrypted.slice(0, encrypted.length - this.info.AESBlockSize);
        }

        return encrypted;
    },

    async webHashSHA256(text) {
        return new Uint8Array(await crypto.subtle.digest("SHA-256", text.buffer));
    },

    async webDecryptAes(cText, intKeyArr, iv0, fs16 = 0) {
        let key = await this.createKey(intKeyArr, "AES-CBC", ["encrypt", "decrypt"]);
        let cTextArr = binaryStream(cText);

        // dirty cheat to add encrypted block pkcs7 padding if mod = 0
        // because WebCrypto subtle working only with pkcs7 pad
        if( fs16 === 0 ) {
            let modBlock = [];

            // xor padding with last block (see mode AES-CBC)
            for( let i = 0; i < this.info.AESBlockSize;i++ ) {
                modBlock.push(0x00 ^ cText[cText.length - this.info.AESBlockSize + i])
            }

            cTextArr.appendBytes( await this.webEncryptAes(new Uint8Array(modBlock), intKeyArr, iv0, false) );
        }

        let pText = new Uint8Array( await crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: iv0,
            },
            key,
            cTextArr.finalize()
        ) );

        // clear empty data pkcs7 padding block
        if( fs16 == 0 ) {
            pText = pText.slice(0, pText.length - this.info.AESBlockSize);
        }

        return pText;
    },
};