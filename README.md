jsAesCrypt

[![Scrutinizer Code Quality](https://img.shields.io/scrutinizer/g/Dead4W/jsAesCrypt.svg?style=flat)](https://scrutinizer-ci.com/g/Dead4W/jsAesCrypt/)

------------------------
jsAesCrypt is a Javascript file-encryption library and script that uses AES256-CBC to encrypt/decrypt files and binary streams.

jsAesCrypt is compatible with the `AES Crypt` `file format` (version 2).

It is Free Software, released under the `Apache License, Version 2.0`.

jsAesCrypt is brought to you by Ilya Zedgenizov - dead4w@gmail.com.
 
**IMPORTANT SECURITY NOTE**: version 2 of the AES Crypt file format does not authenticate the "file size modulo 16" byte. This implies that an attacker  
with write access to the encrypted file may alter the corresponding plaintext file size by up to 15 bytes.

**NOTE**: there is no low-level memory management in Javascript, hence it is not possible to wipe memory areas were sensitive information was stored.

Requirements
------------------------

 - CryptoJS (https://cryptojs.gitbook.io/docs/)
    - core.js
    - cipher-core.js
    - aes.js
    - hmac.js
    - sha256.js
    - pad-nopadding.js
    - enc-utf16.js
 - enc-uint8array.js (Custom Uint8Array encoding)

Library usage example
------------------------
Here is an example showing encryption and decryption of a file:

```javascript
// Init aesCrypt library
const aes = AesCrypt();

var password = "foopassword"
var text = "secret_secret_secret_secret"

// encryption/decryption

// encodeder text to Uint8Array
var enc = new TextEncoder();

// enc.encode(text) === text_words
var text_words = aes.utils.encode_to_words(text);

// encrypt typed array (Uint8Array)
aes.encrypt(enc.encode(text), password).then((encrypted) => {

  // decrypt typed array (Uint8Array)
  aes.decrypt(encrypted, password).then((r) => {

    // transform Uint8Array to Latin1 string
    let result = aes.utils.bytes_to_latin1(decrypted);
    
    console.log(result);
  });
});

// decrypt typed array (Uint8Array)
var decrypted = aes.decrypt(encrypted, password);

// transform Uint8Array to Latin1 string
var result = aes.utils.bytes_to_latin1(decrypted);
```

**This is the most straightforward way to use jsAesCrypt, and should be preferred.**

**jsAesCrypt version can slow working with big files (<100MB)**

FAQs
------------------------
- *Is jsAesCrypt malware?*

  **NO!** Of course it isn't!

  Nevertheless, being a library, it can be used by any other software, including malware.
  
  In fact, it has been reported that it is used as crypto library by some ransomware.

AES Crypt: https://www.aescrypt.com

file format: https://www.aescrypt.com/aes_file_format.html

Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
