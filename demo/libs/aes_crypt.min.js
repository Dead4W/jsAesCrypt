(function () {
    let info = {
        // jsAesCrypt version
        version: "0.12a",

        // encryption/decryption buffer size - 16M
        bufferSize: 16 * 1024 * 1024,

        // file format version
        fileFormatVersion: 0x02,

        // maximum password length (number of chars)
        maxPassLen: 1024,

        // AES block size in bytes
        AESBlockSize: 16,
    };

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
            return utils.bytes_to_latin1(bytes);
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

    var utils = {

        random_int: function(min, max) {
            return Math.floor(Math.random() * (max - min) + min);
        },

        urandom: function(length) {
            let out = "";
            for (let i = 0; i < length; i ++) {
                out += String.fromCharCode(this.random_int(0, 256))
            }
            return out;
        },

        fillArray: function(value, len) {
            let arr = [];
            for (let i = 0; i < len; i ++) {
                arr.push(value);
            }
            return arr;
        },

        arrToInt: function (arr) { // buffer is an UInt8Array
            return parseInt(Array.prototype.map.call(arr, x => ('00' + x.toString(16)).slice(-2)).join(''), 16);
        },

        // bytes is typed array
        bytes_to_latin1: function(bytes) {
            return CryptoJS.enc.Latin1.stringify(CryptoJS.enc.Uint8Arr.parse(bytes))
        },

        encode_to_words: function (input, enc = "Latin1") {
            return CryptoJS.enc[enc].parse(input);
        },

    }
    function createEncryptor(key, iv) {
        return CryptoJS.algo.AES.createEncryptor(utils.encode_to_words(key), {
            mode: CryptoJS.mode.CBC,
            iv: CryptoJS.enc.Latin1.parse(iv),
            padding: CryptoJS.pad.NoPadding,
        });
    }

    function createDecryptor(key, iv) {
        return CryptoJS.algo.AES.createDecryptor(utils.encode_to_words(key), {
            mode: CryptoJS.mode.CBC,
            iv: CryptoJS.enc.Latin1.parse(iv),
            padding: CryptoJS.pad.NoPadding,
        });
    }

    function stretch(passw, iv1) {
        // hash the external iv and the password 8192 times
        let digest = utils.encode_to_words(iv1 + ("\x00".repeat(16)));

        for (let i = 0; i < 8192; i ++) {
            let passHash = CryptoJS.algo.SHA256.create();
            passHash.update(digest);
            passHash.update(utils.encode_to_words(passw, "Utf16LE"));
            digest = passHash.finalize();
        }

        return digest.toString(CryptoJS.enc.Latin1);
    }

    // see https://www.aescrypt.com/aes_file_format.html
    async function createAesCryptFormat(fileObj, iv1, c_iv_key, hmac0, hmac1, encryptor0) {
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
        result = result.appendBytes(utils.fillArray(0x0, 128));

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
        let file = new fileReader(fileObj);

        const blockLength = Math.ceil(file.getLength() / info.bufferSize);

        while( file.getCurrentPosition() < file.getLength() ) {

            let fdata = await file.readBytes(info.bufferSize);

            let bytesRead = fdata.length;

            let cText = encryptor0.process(utils.encode_to_words(fdata, "Uint8Arr")).toString(CryptoJS.enc.Latin1);

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
                cText += encryptor0.process(utils.encode_to_words(padByte)).toString(CryptoJS.enc.Latin1)
            }

            cText += encryptor0.finalize().toString(CryptoJS.enc.Latin1);

            hmac0.update(utils.encode_to_words(cText));

            result = result.appendBytes(cText);

        }

        result = result.appendBytes(fs16);

        // HMAC-SHA256 of the encrypted file
        result = result.appendBytes(hmac0.finalize().toString(CryptoJS.enc.Latin1));

        return await result;
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
     * @param fileObj file element object
     * @param passw string password to decrypt
     */

    async function decrypt(fileObj, passw) {
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
        let iv1 = await file.readBytesAsString(16);
        if( iv1.length !== 16 ) {
            console.warn("File is corrupted.");
            return false;
        }

        // stretch password and iv
        let key = stretch(passw, iv1);

        // read encrypted main iv and key
        let c_iv_key = await file.readBytesAsString(48);
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

        let hmac1Act = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, utils.encode_to_words(key));
        hmac1Act.update(
            utils.encode_to_words(c_iv_key)
        );

        // HMAC check
        if( hmac1 !== CryptoJS.enc.Latin1.stringify(hmac1Act.finalize()) ) {
            console.warn("Wrong password (or file is corrupted).");
            return false;
        }

        // instantiate AES cipher
        let decryptor1 = createDecryptor(key, iv1);

        // decrypt main iv and key
        let iv_key = decryptor1.process(utils.encode_to_words(c_iv_key)).toString(CryptoJS.enc.Latin1) + decryptor1.finalize().toString(CryptoJS.enc.Latin1);

        // get internal iv and key
        let iv0 = iv_key.substr(0, info.AESBlockSize);
        let intKey = iv_key.substr(info.AESBlockSize, 32);

        // instantiate another AES cipher
        let decryptor0 = createDecryptor(intKey, iv0);

        // instantiate actual HMAC-SHA256 of the ciphertext
        let hmac0Act = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, utils.encode_to_words(intKey));

        let result = new Uint8Array([]);

        // decrypt blocks
        while( file.getCurrentPosition() < file.getLength() - 32 - 1 - info.AESBlockSize ) {
            // read data
            let cText = utils.encode_to_words(
                await file.readBytes(
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
            cText = await file.readBytes(info.AESBlockSize);

            if( cText.length < info.AESBlockSize ) {
                console.warn("File is corrupted.");
                return false;
            }
        } else {
            cText = new Uint8Array([]);
        }

        // encode to words for CryptoJS
        cText = utils.encode_to_words(cText, "Uint8Arr");

        // update HMAC
        hmac0Act.update(cText);

        let fs16 = await file.readBytesAsInt(1);

        let pText = decryptor0.process(cText).toString(CryptoJS.enc.Latin1) + decryptor0.finalize().toString(CryptoJS.enc.Latin1);

        // remove padding
        let toremove = ((16 - fs16) % 16);
        if( toremove !== 0 ) {
            pText = pText.substr(0, pText.length - toremove);
        }

        result = result.appendBytes(pText);

        let hmac0 = await file.readBytesAsString(32);

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
     * @param fileObj file element object
     * @param passw string password to encrypt
     */

    async function encrypt(fileObj, passw) {
        if( passw.length > info.maxPassLen ) {
            console.warn("Password is too long.");
            return false;
        }

        // encryption key
        const iv1 = utils.urandom(info.AESBlockSize);

        // stretch password and iv
        const key = stretch(passw, iv1);

        // generate random main iv
        const iv0 = utils.urandom(info.AESBlockSize);

        // generate random internal key
        const intKey = utils.urandom(32);

        const encryptor0 = createEncryptor(intKey, iv0);

        // instantiate HMAC-SHA256 for the ciphertext
        const hmac0 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, utils.encode_to_words(intKey));

        // instantiate another AES cipher
        const encryptor1 = createEncryptor(key, iv1);

        // encrypt main iv and key
        const c_iv_key = encryptor1.process(utils.encode_to_words(iv0 + intKey)).toString(CryptoJS.enc.Latin1) + encryptor1.finalize().toString(CryptoJS.enc.Latin1);

        //# calculate HMAC-SHA256 of the encrypted iv and key
        const hmac1 = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, utils.encode_to_words(key));
        hmac1.update(utils.encode_to_words(c_iv_key));

        return await createAesCryptFormat(fileObj, iv1, c_iv_key, hmac0, hmac1, encryptor0);
    }

    Uint8Array.prototype.appendBytes = function (input) {
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

        let new_uint8_arr = new Uint8Array(this.length + tmp.length);

        new_uint8_arr.set(this);
        new_uint8_arr.set(tmp, this.length);

        return new_uint8_arr;
    }

    function getInfo() {
        return info;
    }

    window.AesCrypt = {
        encrypt: encrypt,
        decrypt: decrypt,
        utils: utils,
        getInfo: getInfo
    }

})