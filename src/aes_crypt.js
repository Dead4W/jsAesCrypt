/** global: aesCrypt */
/** global: webCryptSubtle */
/** global: fileBytesReader */
/** global: binaryStream */

aesCrypt = function () {
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
            return CryptoJS.enc.Latin1.stringify(CryptoJS.enc.Uint8Arr.parse(bytes))
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
            return false;
        }

        // file bytes reader
        let file = fileBytesReader(fileObj);

        // check if file is in AES Crypt format (also min length check)
        if( utils.bytes2str( await file.readBytes(3) ) !== "AES" || file.getLength() < 136 ) {
            throw (
                "File is corrupted or not an AES Crypt \n" +
                        "(or jsAesCrypt) file.");
            return false;
        }

        // check if file is in AES Crypt format, version 2
        // (the only one compatible with jsAesCrypt)
        if( await file.readByte() !== info.fileFormatVersion ) {
            throw (
                "jsAesCrypt is only compatible with version \n" +
                        "2 of the AES Crypt file format.");
            return false;
        }

        // skip reserved byte
        await file.readByte();

        // skip all the extensions
        while(true) {
            let fdata = await file.readBytes(2);

            if( fdata.length < 2 ) {
                throw ("File is corrupted.");
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
            throw ("File is corrupted.");
            return false;
        }

        // _stretch password and iv
        let key = await _stretch(passw, iv1);

        // read encrypted main iv and key
        let ivKey = await file.readBytes(48);
        if( ivKey.length !== 48 ) {
            throw ("File is corrupted.");
            return false;
        }

        // read HMAC-SHA256 of the encrypted iv and key
        let hmac1 = utils.bytes2str( await file.readBytes(32) );
        if( hmac1.length !== 32 ) {
            throw ("File is corrupted.");
            return false;
        }

        let hmac1Act = await webCryptSubtle.webHashHMAC(ivKey, key);

        // HMAC check
        if( hmac1 !== utils.bytes2str(hmac1Act) ) {
            throw ("Wrong password (or file is corrupted).");
            return false;
        }

        ivKey = await webCryptSubtle.webDecryptAes(ivKey, key, iv1, 0);

        // get internal iv and key
        let iv0 = ivKey.slice(0, info.AESBlockSize);
        let intKey = ivKey.slice(info.AESBlockSize, info.AESBlockSize+32);

        let result = binaryStream();

        let cText = binaryStream( await file.readBytes(
            file.getLength() - file.getCurrentPosition() - 32 - 1,
        ));

        let fs16 = utils.arrToInt(await file.readBytes(1));

        hmac0Act = await webCryptSubtle.webHashHMAC(cText.finalize(), intKey); 

        let pText;

        try{
            pText = await webCryptSubtle.webDecryptAes(cText.finalize(), intKey, iv0, fs16);
        } catch {
            // AesCrypt on C# use PKCS7 in pad without full pad block
            // webCrypt can't decrypt it without force cheat with fs16 = 0
            pText = await webCryptSubtle.webDecryptAes(cText.finalize(), intKey, iv0, 0);
            let toremove = info.AESBlockSize - fs16;
            pText = pText.slice(0, pText.length - toremove);
        }

        result.appendBytes(pText);

        let hmac0 = utils.bytes2str( await file.readBytes(32) );

        if( hmac0.length !== 32 ) {
            throw ("File is corrupted.");
            return false;
        }

        if( hmac0 !== utils.bytes2str(hmac0Act) ) {
            throw ("Bad HMAC (file is corrupted).");
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
     */

    async function encrypt(fileObj, passw) {
        if( passw.length > info.maxPassLen ) {
            throw ("Password is too long.");
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

        let ivKey = binaryStream();
        ivKey.appendBytes(iv0);
        ivKey.appendBytes(intKey);

        // encrypt main iv and key
        ivKey = await webCryptSubtle.webEncryptAes(ivKey.finalize(), key, iv1);

        const hmac1 = await webCryptSubtle.webHashHMAC(ivKey, key);

        return await _createAesCryptFormat(fileObj, iv1, ivKey, intKey, hmac1, iv0);
    }

    /* PRIVATE START */

    // IMPORT webCryptSubtle THIS
    // IMPORT fileBytesReader THIS
    // IMPORT binaryStream THIS

    // stretch password and iv1
    async function _stretch(passw, iv1) {
        // hash the external iv and the password 8192 times
        let digest = binaryStream();
        digest.appendBytes(iv1);
        digest.appendBytes("\x00".repeat(16));

        digest = digest.finalize();

        for (let i = 0; i < 8192; i ++) {
            let passHash = binaryStream(digest);
            passHash.appendBytes(utils.str2bytes(passw, "Utf16LE"));
            digest = await webCryptSubtle.webHashSHA256(passHash.finalize(0));
        }

        return digest;
    }

    // see https://www.aescrypt.com/aes_file_format.html
    async function _createAesCryptFormat(fileObj, iv1, ivKey, intKey, hmac1, iv0) {
        let result = binaryStream();

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

        let file = new fileBytesReader(fileObj);
        let bytesRead = file.getLength();
        let pText = binaryStream( 
            await file.readBytes( file.getLength() )
        );

        // file size mod 16, lsb positions
        let fs16 = String.fromCharCode(bytesRead % info.AESBlockSize);

        cText = await webCryptSubtle.webEncryptAes(pText.finalize(), intKey ,iv0);

        hmac0 = await webCryptSubtle.webHashHMAC(cText, intKey);

        result.appendBytes(cText);

        result.appendBytes(fs16);

        // HMAC-SHA256 of the encrypted file
        result.appendBytes(hmac0);

        return await result.finalize();
    }

    webCryptSubtle.info = info;

    return {
        encrypt,
        decrypt,
        utils,
        info
    };

};