AesCrypt = function () {

    const info = {
        // jsAesCrypt version
        version: "0.1",

        // encryption/decryption buffer size - 8M
        bufferSize: 8 * 1024 * 1024,

        // file format version
        fileFormatVersion: 0x02,

        // maximum password length (number of chars)
        maxPassLen: 1024,

        // AES block size in bytes
        AESBlockSize: 16,
    };

    function createEncryptor(key, iv) {
        return CryptoJS.algo.AES.createEncryptor(Utilities.encode_to_words(key), {
            mode: CryptoJS.mode.CBC,
            iv: CryptoJS.enc.Latin1.parse(iv),
            padding: CryptoJS.pad.NoPadding,
        });
    }

    function createDecryptor(key, iv) {
        return CryptoJS.algo.AES.createDecryptor(Utilities.encode_to_words(key), {
            mode: CryptoJS.mode.CBC,
            iv: CryptoJS.enc.Latin1.parse(iv),
            padding: CryptoJS.pad.NoPadding,
        });
    }

    function stretch(passw, iv1) {
        // hash the external iv and the password 8192 times
        let digest = Utilities.encode_to_words(iv1 + ("\x00".repeat(16)));

        for (let i = 0; i < 8192; i ++) {
            const passHash = CryptoJS.algo.SHA256.create();
            passHash.update(digest);
            passHash.update(Utilities.encode_to_words(passw, "Utf16LE"));
            digest = passHash.finalize();
        }

        return digest.toString(CryptoJS.enc.Latin1);
    }

    // see https://www.aescrypt.com/aes_file_format.html
    function createAesCryptFormat(content, iv1, c_iv_key, hmac0, hmac1, encryptor0) {
        let result = new Uint8Array([]);

        // header
        result = result.appendBytes("AES");

        // version (AES Crypt version 2 file format -
        // see https://www.aescrypt.com/aes_file_format.html)
        result = result.appendBytes(info.fileFormatVersion);

        // reserved byte (set to zero)
        result = result.appendBytes(0x0);

        // setup "CREATED-BY" extension
        const cby = "jsAesCrypt " + info.version;

        // "CREATED-BY" extension length
        result = result.appendBytes(0x0);
        result = result.appendBytes(1 + ("CREATED_BY" + cby).length);

        // "CREATED-BY" extension
        result = result.appendBytes("CREATED_BY");
        result = result.appendBytes(0x0);
        result = result.appendBytes(cby);

        // "container" extension length
        result = result.appendBytes([0x0, 0x80]);

        // "container" extension
        result = result.appendBytes(Utilities.fillArray(0x0, 128));

        // end-of-extensions tag
        result = result.appendBytes([0x0, 0x0]);

        // the iv used to encrypt the main iv and the
        // encryption key
        result = result.appendBytes(iv1);

        // encrypted main iv and key
        result = result.appendBytes(c_iv_key);

        // HMAC-SHA256 of the encrypted iv and key
        result = result.appendBytes(hmac1.finalize().toString(CryptoJS.enc.Latin1));

        let fs16 = String.fromCharCode(0);
        const blockLength = Math.ceil(content.byteLength / info.bufferSize);

        for (let i = 0; i < blockLength; i++) {

            let fdata = new Uint8Array(content.slice(i * info.bufferSize, (i + 1) * info.bufferSize));

            let bytesRead = fdata.length;

            let cText = encryptor0.process(Utilities.encode_to_words(fdata, "Uint8Arr")).toString(CryptoJS.enc.Latin1);

            // check if EOF was reached
            if (bytesRead < info.bufferSize) {
                // file size mod 16, lsb positions
                fs16 = String.fromCharCode(bytesRead % info.AESBlockSize);
                // pad data (this is NOT PKCS#7!)
                // ...unless no bytes or a multiple of a block size
                // of bytes was read
                let padLen;
                if (bytesRead % info.AESBlockSize === 0) {
                    padLen = 0;
                } else {
                    padLen = 16 - bytesRead % info.AESBlockSize;
                }

                let padByte = fs16.repeat(padLen);

                // encrypt data
                cText += encryptor0.process(Utilities.encode_to_words(padByte)).toString(CryptoJS.enc.Latin1)
            }

            cText += encryptor0.finalize().toString(CryptoJS.enc.Latin1);

            hmac0.update(Utilities.encode_to_words(cText));

            result = result.appendBytes(cText);

        }

        result = result.appendBytes(fs16);

        // HMAC-SHA256 of the encrypted file
        result = result.appendBytes(hmac0.finalize().toString(CryptoJS.enc.Latin1));

        return result;
    }

    /**
     * decrypt typed array
     *
     *
     * @return The Uint8Array.
     *
     * @static
     *
     * @example
     *     var decrypted = decrypt(typedArray, Password);
     *
     * @param content decrypted typed array
     * @param passw string password to decrypt
     */

    function decrypt(content, passw) {
        if( passw.length > info.maxPassLen ) {
            console.warn("Password is too long.");
            return false;
        }

        // file bytes reader
        const file = Utilities.fileReader(new Uint8Array(content));

        // check if file is in AES Crypt format (also min length check)
        if( file.readBytesAsString(3) !== "AES" || file.getLength() < 136 ) {
            console.warn(
                "File is corrupted or not an AES Crypt \n" +
                        "(or jsAesCrypt) file.");
            return false;
        }

        // check if file is in AES Crypt format, version 2
        // (the only one compatible with jsAesCrypt)
        if( file.readByte() !== info.fileFormatVersion ) {
            console.warn(
                "jsAesCrypt is only compatible with version \n" +
                        "2 of the AES Crypt file format.");
            return false;
        }

        // skip reserved byte
        file.readByte()

        // skip all the extensions
        while(true) {
            let fdata = file.readBytes(2);

            if( fdata.length < 2 ) {
                console.warn("File is corrupted.");
                return false;
            }

            fdata = +Utilities.arrToInt(fdata);

            if( fdata === 0 ) {
                break;
            }

            file.readBytes(
                fdata
            );
        }

        // read external iv
        const iv1 = file.readBytesAsString(16);
        if( iv1.length !== 16 ) {
            console.warn("File is corrupted.");
            return false;
        }

        // stretch password and iv
        const key = stretch(passw, iv1);

        // read encrypted main iv and key
        const c_iv_key = file.readBytesAsString(48);
        if( c_iv_key.length !== 48 ) {
            console.warn("File is corrupted.");
            return false;
        }

        // read HMAC-SHA256 of the encrypted iv and key
        const hmac1 = file.readBytesAsString(32);
        if( hmac1.length !== 32 ) {
            console.warn("File is corrupted.");
            return false;
        }

        const hmac1Act = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, Utilities.encode_to_words(key));
        hmac1Act.update(
            Utilities.encode_to_words(c_iv_key)
        );

        // HMAC check
        if( hmac1 !== CryptoJS.enc.Latin1.stringify(hmac1Act.finalize()) ) {
            console.warn("Wrong password (or file is corrupted).");
            return false;
        }

        // instantiate AES cipher
        const decryptor1 = createDecryptor(key, iv1);

        // decrypt main iv and key
        const iv_key = decryptor1.process(Utilities.encode_to_words(c_iv_key)).toString(CryptoJS.enc.Latin1) + decryptor1.finalize().toString(CryptoJS.enc.Latin1);

        // get internal iv and key
        const iv0 = iv_key.substr(0, info.AESBlockSize);
        const intKey = iv_key.substr(info.AESBlockSize, 32);

        // instantiate another AES cipher
        const decryptor0 = createDecryptor(intKey, iv0);

        // instantiate actual HMAC-SHA256 of the ciphertext
        const hmac0Act = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, Utilities.encode_to_words(intKey));

        let result = new Uint8Array([]);

        // decrypt blocks
        while( file.getCurrentPosition() < file.getLength() - 32 - 1 - info.AESBlockSize ) {
            // read data
            let cText = Utilities.encode_to_words(
                file.readBytes(
                    Math.min(
                        info.bufferSize,
                        file.getLength() - file.getCurrentPosition() - 32 - 1 - info.AESBlockSize,
                    )
                ),
                "Uint8Arr"
            )

            // update HMAC
            hmac0Act.update(cText)
            // decrypt data and write it to output file
            result = result.appendBytes(decryptor0.process(cText).toString(CryptoJS.enc.Latin1));
        }

        var cText;

        // last block reached, remove padding if needed
        // read last block
        if( file.getCurrentPosition() !== file.getLength() - 32 - 1 ) {
            // read typed array
            cText = file.readBytes(info.AESBlockSize);

            if( cText.length < info.AESBlockSize ) {
                console.warn("File is corrupted.");
                return false;
            }
        } else {
            cText = new Uint8Array([]);
        }

        // encode to words for CryptoJS
        cText = Utilities.encode_to_words(cText, "Uint8Arr");

        // update HMAC
        hmac0Act.update(cText);

        const fs16 = file.readBytesAsInt(1);

        let pText = decryptor0.process(cText).toString(CryptoJS.enc.Latin1) + decryptor0.finalize().toString(CryptoJS.enc.Latin1);

        // remove padding
        const toremove = ((16 - fs16) % 16);
        if( toremove !== 0 ) {
            pText = pText.substr(0, pText.length - toremove);
        }

        result = result.appendBytes(pText);

        const hmac0 = file.readBytesAsString(32);

        if( hmac0.length !== 32 ) {
            console.warn("File is corrupted.");
            return false;
        }

        if( hmac0 !== CryptoJS.enc.Latin1.stringify(hmac0Act.finalize()) ) {
            console.warn("Bad HMAC (file is corrupted).");
            return false;
        }

        return result;
    }

    /**
     * encrypt typed array
     *
     *
     * @return The Uint8Array.
     *
     * @static
     *
     * @example
     *     var encrypted = encrypt(typedArray, Password);
     *
     * @param content typed array
     * @param passw string password to encrypt
     */

    function encrypt(content, passw) {
        if( passw.length > info.maxPassLen ) {
            console.warn("Password is too long.");
            return false;
        }

        // encryption key
        const iv1 = Utilities.urandom(info.AESBlockSize);

        // stretch password and iv
        const key = stretch(passw, iv1);

        // generate random main iv
        const iv0 = Utilities.urandom(info.AESBlockSize);

        // generate random internal key
        const intKey = Utilities.urandom(32);

        const encryptor0 = createEncryptor(intKey, iv0);

        // instantiate HMAC-SHA256 for the ciphertext
        const hmac0 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, Utilities.encode_to_words(intKey));

        // instantiate another AES cipher
        const encryptor1 = createEncryptor(key, iv1);

        // encrypt main iv and key
        const c_iv_key = encryptor1.process(Utilities.encode_to_words(iv0 + intKey)).toString(CryptoJS.enc.Latin1) + encryptor1.finalize().toString(CryptoJS.enc.Latin1);

        //# calculate HMAC-SHA256 of the encrypted iv and key
        const hmac1 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, Utilities.encode_to_words(key));
        hmac1.update(Utilities.encode_to_words(c_iv_key));

        return createAesCryptFormat(content, iv1, c_iv_key, hmac0, hmac1, encryptor0);
    }

    Uint8Array.prototype.appendBytes = function (input) {
        let tmp;

        if (typeof (input) == "number") {
            const hex_string = input.toString(16);
            tmp = new Uint8Array(hex_string.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        } else if (typeof (input) == "string") {
            tmp = new Uint8Array(input.length);
            for (let i = 0; i < input.length; i ++) {
                tmp[i] = input.charCodeAt(i);
            }
        } else {
            tmp = new Uint8Array(input);
        }

        const new_uint8_arr = new Uint8Array(this.length + tmp.length);

        new_uint8_arr.set(this);
        new_uint8_arr.set(tmp, this.length);

        return new_uint8_arr;
    }

    function getInfo() {
        return info;
    }

    return {
        encrypt: encrypt,
        decrypt: decrypt,
        createEncryptor: createEncryptor,
        getInfo: getInfo
    }

}

const saveByteArray = (function () {
    return function (data, name) {
        const a = document.createElement("a");
        document.body.appendChild(a);
        a.style = "display: none";

        const blob = new Blob([data], {type: "octet/stream"}),
            url = window.URL.createObjectURL(blob);
        a.href = url;
        a.download = name;
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    };
}());