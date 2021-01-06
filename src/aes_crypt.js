AesCrypt = function () {
    let info = {
        // jsAesCrypt version
        version: "0.15",

        // encryption/decryption buffer size - 32K
        bufferSize: 32 * 1024,

        // file format version
        fileFormatVersion: 0x02,

        // maximum password length (number of chars)
        maxPassLen: 1024,

        // AES block size in bytes
        AESBlockSize: 16,
    };


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
     * @param fileObj file element object
     * @param passw string password to decrypt
     * @callback_progress callback function (current) => { 0 < current <= 1 }
     */

    async function decrypt(fileObj, passw, callback_progress = (c) => {}) {
        if( passw.length > info.maxPassLen ) {
            console.warn("Password is too long.");
            return false;
        }

        // file bytes reader
        let file = fileReader(fileObj);

        // check if file is in AES Crypt format (also min length check)
        if( await file.readBytesAsString(3) !== "AES" || file.getLength() < 136 ) {
            console.warn(
                "File is corrupted or not an AES Crypt \n" +
                        "(or jsAesCrypt) file.");
            return false;
        }

        // check if file is in AES Crypt format, version 2
        // (the only one compatible with jsAesCrypt)
        if( await file.readByte() !== info.fileFormatVersion ) {
            console.warn(
                "jsAesCrypt is only compatible with version \n" +
                        "2 of the AES Crypt file format.");
            return false;
        }

        // skip reserved byte
        await file.readByte()

        // skip all the extensions
        while(true) {
            let fdata = await file.readBytes(2);

            if( fdata.length < 2 ) {
                console.warn("File is corrupted.");
                return false;
            }

            fdata = +utils.arrToInt(fdata);

            if( fdata === 0 ) {
                break;
            }

            await file.readBytes(
                fdata
            );
        }

        // read external iv
        let iv1 = await file.readBytes(16);
        if( iv1.length !== 16 ) {
            console.warn("File is corrupted.");
            return false;
        }

        // _stretch password and iv
        let key = await _stretch(passw, iv1);

        // read encrypted main iv and key
        let c_iv_key = await file.readBytes(48);
        if( c_iv_key.length !== 48 ) {
            console.warn("File is corrupted.");
            return false;
        }

        // read HMAC-SHA256 of the encrypted iv and key
        let hmac1 = await file.readBytesAsString(32);
        if( hmac1.length !== 32 ) {
            console.warn("File is corrupted.");
            return false;
        }

        let hmac1Act = await _webHashHMAC(c_iv_key, key);

        // HMAC check
        if( hmac1 !== utils.bytes2str(hmac1Act) ) {
            console.warn("Wrong password (or file is corrupted).");
            return false;
        }

        let iv_key = await _webDecryptAes(c_iv_key, key, iv1, 0);

        // get internal iv and key
        let iv0 = iv_key.slice(0, info.AESBlockSize);
        let intKey = iv_key.slice(info.AESBlockSize, info.AESBlockSize+32);

        let result = binaryArray();

        let cText = binaryArray( await file.readBytes(
            file.getLength() - file.getCurrentPosition() - 32 - 1,
        ));

        let fs16 = await file.readBytesAsInt(1);

        hmac0Act = await _webHashHMAC(cText.finalize(), intKey); 

        let pText;

        try{
            pText = await _webDecryptAes(cText.finalize(), intKey, iv0, fs16);
        } catch {
            // AesCrypt on C# use PKCS7 in pad without full pad block
            // webCrypt can't decrypt it
            pText = await _webDecryptAes(cText.finalize(), intKey, iv0, 0);
            let toremove = info.AESBlockSize - fs16;
            pText = pText.slice(0, pText.length - toremove);
        }

        result.appendBytes(pText);

        let hmac0 = await file.readBytesAsString(32);

        if( hmac0.length !== 32 ) {
            console.warn("File is corrupted.");
            return false;
        }

        if( hmac0 !== utils.bytes2str(hmac0Act) ) {
            console.warn("Bad HMAC (file is corrupted).");
            return false;
        }

        return result.finalize();
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
     * @param fileObj file element object
     * @param passw string password to encrypt
     * @callback_progress callback function (current) => { 0 < current <= 1 }
     */

    async function encrypt(fileObj, passw, callback_progress = (c) => {}) {
        if( passw.length > info.maxPassLen ) {
            console.warn("Password is too long.");
            return false;
        }

        // encryption key
        const iv1 = utils.urandom(info.AESBlockSize);

        // _stretch password and iv
        const key = await _stretch(passw, iv1);

        // generate random main iv
        const iv0 = utils.urandom(info.AESBlockSize);

        // generate random internal key
        const intKey = utils.urandom(32);

        let iv0_and_intkey = binaryArray();
        iv0_and_intkey.appendBytes(iv0);
        iv0_and_intkey.appendBytes(intKey);

        // encrypt main iv and key
        const c_iv_key = await _webEncryptAes(iv0_and_intkey.finalize(), key, iv1);

        const hmac1 = await _webHashHMAC(c_iv_key, key);

        return await _createAesCryptFormat(fileObj, iv1, c_iv_key, intKey, hmac1, iv0, callback_progress);
    }

    /* PRIVATE START */

    // private class fileReader for read file by blocks
    var fileReader = function(file) {
        let _i = 0;
        let _fileSize = file.size;
        let _reader = new FileReader();
        let _file = file;

        function readChunk(length) {
            return new Promise((resolve, reject) => {
                let blob = _file.slice(_i, _i += length);

                _reader.onload = () => {
                    // return Uint8Array
                    resolve(new Uint8Array(_reader.result));
                };

                _reader.onerror = reject;

                _reader.readAsArrayBuffer(blob);
            });
        }

        async function readBytes(length) {
            return await readChunk(length);
        }

        async function readByte() {
            let bytes = await readBytes(1);
            return bytes[0];
        }

        async function readBytesAsString(length) {
            let bytes = await readBytes(length);
            return utils.bytes2str(bytes);
        }

        async function readBytesAsInt(length) {
            let bytes = await readBytes(length);
            return utils.arrToInt(bytes);
        }

        function getCurrentPosition() {
            return _i;
        }

        function getLength() {
            return _fileSize;
        }

        return {
            readByte: readByte,
            readBytes: readBytes,
            readBytesAsInt: readBytesAsInt,
            readBytesAsString: readBytesAsString,
            getCurrentPosition: getCurrentPosition,
            getLength: getLength,
        };
    };

    // private class utils for usefull functions
    var utils = {

        urandom: function(length) {
            return crypto.getRandomValues( new Uint8Array(length) );
        },

        arrToInt: function (arr) { // buffer is an UInt8Array
            return parseInt(Array.prototype.map.call(arr, x => ('00' + x.toString(16)).slice(-2)).join(''), 16);
        },

        // bytes is typed array
        bytes2str: function(bytes) {
            return CryptoJS.enc.Latin1.stringify(CryptoJS.enc.Uint8Arr.parse(bytes))
        },

        str2bytes: function(str, enc="Latin1") {
            return CryptoJS.enc.Uint8Arr.decode(CryptoJS.enc[enc].parse(str));
        },

    }

    // private class binaryArray for easy work with Uint8Array
    let binaryArray = function(arr = []) {
        let _data = new Uint8Array(arr);

        function appendBytes(input) {
            let tmp;

            if (typeof (input) == "number") {
                let hex_string = input.toString(16);
                tmp = new Uint8Array(hex_string.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            } else if (typeof (input) == "string") {
                tmp = new Uint8Array(input.length);
                for (let i = 0; i < input.length; i ++) {
                    tmp[i] = input.charCodeAt(i);
                }
            } else {
                tmp = new Uint8Array(input);
            }

            let new_uint8_arr = new Uint8Array(_data.length + tmp.length);

            new_uint8_arr.set(_data);
            new_uint8_arr.set(tmp, _data.length);

            _data = new_uint8_arr;
        };

        function get(i) {
            return _data[i];
        }

        function finalize() {
            return _data;
        };

        function getLength() {
            return _data.length;
        }

        return {
            appendBytes: appendBytes,
            finalize: finalize,
            get: get,
            getLength: getLength,
        }
    }

    async function _createKey(intKeyArr, mode, functions) {
        return await crypto.subtle.importKey( "raw", intKeyArr.buffer,   mode ,  false,   functions);
    }

    async function _webHashHMAC(text, intKeyArr) {
        let key_encoded = await _createKey(
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
    }

    async function _webEncryptAes(pText, intKeyArr, iv0, stayLast=true) {
        let key_encoded = await _createKey(intKeyArr, "AES-CBC", ["encrypt", "decrypt"]);

        let encrypted = new Uint8Array( await crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: iv0,
            },
            key_encoded,
            pText
        ) );

        if( pText.length % info.AESBlockSize === 0 && stayLast == true ) {
            encrypted = encrypted.slice(0, encrypted.length - info.AESBlockSize);
        }

        return encrypted;
    }

    async function _webHashSHA256(text) {
        return new Uint8Array(await crypto.subtle.digest("SHA-256", text.buffer));
    }

    async function _webDecryptAes(cText, intKeyArr, iv0, fs16 = 0) {
        let key_encoded = await _createKey(intKeyArr, "AES-CBC", ["encrypt", "decrypt"]);
        let cTextArr = binaryArray(cText);

        // dirty cheat to add encrypted block pkcs7 padding if mod = 0
        // because WebCrypto subtle working only with pkcs7 pad
        if( fs16 == 0 ) {
            let modBlock = new Uint8Array(info.AESBlockSize);

            // xor padding with last block (see mode AES-CBC)
            for( let i = 0; i < info.AESBlockSize;i++ ) {
                modBlock[i] = 0x00 ^ cText[cText.length - info.AESBlockSize + i];
            }

            modBlockEncrypted = await _webEncryptAes(modBlock, intKeyArr, iv0, false);

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
            pText = pText.slice(0, pText.length - info.AESBlockSize);
        }

        return pText;
    }

    // stretch password and iv1
    async function _stretch(passw, iv1) {
        // hash the external iv and the password 8192 times
        let digest_tmp = binaryArray();
        digest_tmp.appendBytes(iv1);
        digest_tmp.appendBytes("\x00".repeat(16));

        let digest = digest_tmp.finalize();

        for (let i = 0; i < 8192; i ++) {
            let passHash = binaryArray(digest);
            passHash.appendBytes(utils.str2bytes(passw, "Utf16LE"));
            digest = await _webHashSHA256(passHash.finalize(0));
        }

        return digest;
    }

    // see https://www.aescrypt.com/aes_file_format.html
    async function _createAesCryptFormat(fileObj, iv1, c_iv_key, intKey, hmac1, iv0, callback_progress) {
        let result = binaryArray();

        // header
        result.appendBytes("AES");

        // version (AES Crypt version 2 file format -
        // see https://www.aescrypt.com/aes_file_format.html)
        result.appendBytes(info.fileFormatVersion);

        // reserved byte (set to zero)
        result.appendBytes(0x0);

        // setup "CREATED-BY" extension
        const cby = "jsAesCrypt " + info.version;

        // "CREATED-BY" extension length
        result.appendBytes(0x0);
        result.appendBytes(1 + ("CREATED_BY" + cby).length);

        // "CREATED-BY" extension
        result.appendBytes("CREATED_BY");
        result.appendBytes(0x0);
        result.appendBytes(cby);

        // "container" extension length
        result.appendBytes([0x0, 0x80]);

        // "container" extension
        result.appendBytes("\x00".repeat(128));

        // end-of-extensions tag
        result.appendBytes([0x0, 0x0]);

        // the iv used to encrypt the main iv and the
        // encryption key
        result.appendBytes(iv1);

        // encrypted main iv and key
        result.appendBytes(c_iv_key);

        // HMAC-SHA256 of the encrypted iv and key
        result.appendBytes(hmac1);

        let file = new fileReader(fileObj);
        let bytesRead = file.getLength();
        let pText = binaryArray( 
            await file.readBytes( file.getLength() )
        );

        // file size mod 16, lsb positions
        let fs16 = String.fromCharCode(bytesRead % info.AESBlockSize);

        cText = await _webEncryptAes(pText.finalize(), intKey ,iv0);

        hmac0 = await _webHashHMAC(cText, intKey);

        result.appendBytes(cText);

        result.appendBytes(fs16);

        // HMAC-SHA256 of the encrypted file
        result.appendBytes(hmac0);

        return await result.finalize();
    }

    return {
        encrypt: encrypt,
        decrypt: decrypt,
        utils: utils,
        info: info
    }

};