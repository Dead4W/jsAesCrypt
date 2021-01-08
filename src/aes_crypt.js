/** global: aesCrypt */

var aesCrypt;

(function () {

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

    const utils = {

        urandom(length) {
            return crypto.getRandomValues( new Uint8Array(length) );
        },

        arrToInt (arr) { // buffer is an UInt8Array
            return parseInt(Array.prototype.map.call(arr, x => ('00' + x.toString(16)).slice(-2)).join(''), 16);
        },

        // bytes is typed array
        bytes2str(bytes) {
            return CryptoJS.enc.Latin1.stringify(CryptoJS.enc.Uint8Arr.parse(bytes));
        },

        str2bytes(str, enc="Latin1") {
            return CryptoJS.enc.Uint8Arr.decode(CryptoJS.enc[enc].parse(str));
        },

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
            throw ("Password is too long.");
        }

        // file bytes reader
        let file = new self.FileBytesReader(fileObj);

        // check if file is in AES Crypt format (also min length check)
        if( utils.bytes2str( await file.readBytes(3) ) !== "AES" || file.getLength() < 136 ) {
            throw (
                "File is corrupted or not an AES Crypt \n" +
                        "(or jsAesCrypt) file.");
        }

        // check if file is in AES Crypt format, version 2
        // (the only one compatible with jsAesCrypt)
        if( await file.readByte() !== info.fileFormatVersion ) {
            throw (
                "jsAesCrypt is only compatible with version \n" +
                        "2 of the AES Crypt file format.");
        }

        // skip reserved byte
        await file.readByte();

        // skip all the extensions
        while(true) {
            let fdata = await file.readBytes(2);

            if( fdata.length < 2 ) {
                throw ("File is corrupted.");
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
            throw ("File is corrupted.");
        }

        // _stretch password and iv
        let key = await _stretch(passw, iv1);

        // read encrypted main iv and key
        let ivKey = await file.readBytes(48);
        if( ivKey.length !== 48 ) {
            throw ("File is corrupted.");
        }

        // read HMAC-SHA256 of the encrypted iv and key
        let hmac1 = utils.bytes2str( await file.readBytes(32) );
        if( hmac1.length !== 32 ) {
            throw ("File is corrupted.");
        }

        let hmac1Act = await self.webCryptSubtle.webHashHMAC(ivKey, key);

        // HMAC check
        if( hmac1 !== utils.bytes2str(hmac1Act) ) {
            throw ("Wrong password (or file is corrupted).");
        }

        ivKey = await self.webCryptSubtle.webDecryptAes(ivKey, key, iv1, 0);

        // get internal iv and key
        let iv0 = ivKey.slice(0, info.AESBlockSize);
        let intKey = ivKey.slice(info.AESBlockSize, info.AESBlockSize+32);

        let result = new self.BinaryStream();

        let cText = new self.BinaryStream( await file.readBytes(
            file.getLength() - file.getCurrentPosition() - 32 - 1,
        ));

        let fs16 = utils.arrToInt(await file.readBytes(1));

        let hmac0Act = await self.webCryptSubtle.webHashHMAC(cText.finalize(), intKey); 

        let pText;

        try{
            pText = await self.webCryptSubtle.webDecryptAes(cText.finalize(), intKey, iv0, fs16);
        } catch {
            // AesCrypt on C# use PKCS7 in pad without full pad block
            // webCrypt can't decrypt it without force cheat with fs16 = 0
            pText = await self.webCryptSubtle.webDecryptAes(cText.finalize(), intKey, iv0, 0);
            let toremove = info.AESBlockSize - fs16;
            pText = pText.slice(0, pText.length - toremove);
        }

        result.appendBytes(pText);

        let hmac0 = utils.bytes2str( await file.readBytes(32) );

        if( hmac0.length !== 32 ) {
            throw ("File is corrupted.");
        }

        if( hmac0 !== utils.bytes2str(hmac0Act) ) {
            throw ("Bad HMAC (file is corrupted).");
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
     */

    async function encrypt(fileObj, passw) {
        if( passw.length > info.maxPassLen ) {
            throw ("Password is too long.");
        }

        // encryption key
        const iv1 = utils.urandom(info.AESBlockSize);

        // _stretch password and iv
        const key = await _stretch(passw, iv1);

        // generate random main iv
        const iv0 = utils.urandom(info.AESBlockSize);

        // generate random internal key
        const intKey = utils.urandom(32);

        let ivKey = new self.BinaryStream();
        ivKey.appendBytes(iv0);
        ivKey.appendBytes(intKey);

        // encrypt main iv and key
        ivKey = await self.webCryptSubtle.webEncryptAes(ivKey.finalize(), key, iv1);

        const hmac1 = await self.webCryptSubtle.webHashHMAC(ivKey, key);

        return await _createAesCryptFormat(fileObj, iv1, ivKey, intKey, hmac1, iv0);
    }

    /* PRIVATE START */

    // stretch password and iv1
    async function _stretch(passw, iv1) {
        let passwArr = CryptoJS.enc.Uint8Arr.decode(CryptoJS.enc.Utf16LE.parse(passw))

        
        // add 16 null bytes to iv1 at the end
        let digest = new self.BinaryStream();
        digest.appendBytes(iv1);
        digest.appendBytes("\x00".repeat(16));

        digest = digest.finalize();


        // hash the external iv and the password 8192 times
        for (let i = 0; i < 8192; i ++) {
            let passHash = new self.BinaryStream(digest);
            passHash.appendBytes(passwArr);
            digest = await self.webCryptSubtle.webHashSHA256(passHash.finalize());
        }

        return digest;
    }

    // see https://www.aescrypt.com/aes_file_format.html
    async function _createAesCryptFormat(fileObj, iv1, ivKey, intKey, hmac1, iv0) {
        let result = new self.BinaryStream();

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
        result.appendBytes(ivKey);

        // HMAC-SHA256 of the encrypted iv and key
        result.appendBytes(hmac1);

        let file = new self.FileBytesReader(fileObj);
        let bytesRead = file.getLength();
        let pText = new self.BinaryStream( 
            await file.readBytes( file.getLength() )
        );

        // file size mod 16, lsb positions
        let fs16 = String.fromCharCode(bytesRead % info.AESBlockSize);

        let cText = await self.webCryptSubtle.webEncryptAes(pText.finalize(), intKey ,iv0);

        let hmac0 = await self.webCryptSubtle.webHashHMAC(cText, intKey);

        result.appendBytes(cText);

        result.appendBytes(fs16);

        // HMAC-SHA256 of the encrypted file
        result.appendBytes(hmac0);

        return await result.finalize();
    }

    var self = aesCrypt = {
        encrypt,
        decrypt,
        utils,
        info
    };

    if( typeof(window) !== "undefined" ) window.aesCrypt = self;

}());


/** global: FileBytesReader */
/** global: FileReader */

/**
 * read file as string, bytes (uint8Array), int (1 byte)
 *
 *
 * @return The FileBytesReader object.
 *
 * @static
 *
 * @example
 *     var fileElement = document.getElementById('file').files[0];
 *     var file = new FileBytesReader(fileElement);
 *
 * @param file a fileElement object
 */

(function () {
    let LIB = aesCrypt;
    aesCrypt.FileBytesReader = function(file) {
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

        function getCurrentPosition() {
            return _i;
        }

        function getLength() {
            return _fileSize;
        }

        return {
            readByte,
            readBytes,
            getCurrentPosition,
            getLength,
        };
    };

}());


/** global: BinaryStream */

/**
 * binary array stream object
 *
 *
 * @return The BinaryStream object.
 *
 * @static
 *
 * @example
 *     var BinaryStream = BinaryStream([1,2,3]);
 *     BinaryStream.appendBytes([4,5,6]);
 *     BinaryStream.appendBytes("\x07\x08\x09");
 *     console.log(BinaryStream.finalize()) // returns Uint8Array [1,2,3,4,5,6,7,8,9]
 *
 * @param arr origin array
 */

(function () {
    let LIB = aesCrypt;
    aesCrypt.BinaryStream = function(arr = []) {
        let _data = new Uint8Array(arr);

        function appendBytes(input) {
            let tmp;

            if (typeof (input) == "number") {
                let hex = input.toString(16);
                tmp = new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
            } else if (typeof (input) == "string") {
                tmp = new Uint8Array(input.length);
                for (let i = 0; i < input.length; i ++) {
                    tmp[i] = input.charCodeAt(i);
                }
            } else {
                tmp = new Uint8Array(input);
            }

            let tmpArr = new Uint8Array(_data.length + tmp.length);

            tmpArr.set(_data);
            tmpArr.set(tmp, _data.length);

            _data = tmpArr;
        }

        function get(i) {
            return _data[i];
        }

        function finalize() {
            return _data;
        }

        function getLength() {
            return _data.length;
        }

        return {
            appendBytes,
            finalize,
            get,
            getLength,
        }
    };
}());

/** global: webCryptSubtle */

(function () {
    let LIB = aesCrypt;

    aesCrypt.webCryptSubtle = {

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

            if( pText.length % LIB.info.AESBlockSize === 0 && stayLast === true ) {
                encrypted = encrypted.slice(0, encrypted.length - LIB.info.AESBlockSize);
            }

            return encrypted;
        },

        async webHashSHA256(text) {
            return new Uint8Array(await crypto.subtle.digest("SHA-256", text.buffer));
        },

        async webDecryptAes(cText, intKeyArr, iv0, fs16 = 0) {
            let key = await this.createKey(intKeyArr, "AES-CBC", ["encrypt", "decrypt"]);
            let cTextArr = new LIB.BinaryStream(cText);

            // dirty cheat to add encrypted block pkcs7 padding if mod = 0
            // because WebCrypto subtle working only with pkcs7 pad
            if( fs16 === 0 ) {
                let modBlock = [];

                // xor padding with last block (see mode AES-CBC)
                for( let i = 0; i < LIB.info.AESBlockSize;i++ ) {
                    modBlock.push(0x00 ^ cText[cText.length - LIB.info.AESBlockSize + i])
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
            if( fs16 === 0 ) {
                pText = pText.slice(0, pText.length - LIB.info.AESBlockSize);
            }

            return pText;
        },
    };
}());