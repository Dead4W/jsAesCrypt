# jsAesCrypt

[![HitCount](http://hits.dwyl.com/Dead4W/jsAesCrypt.svg)](http://hits.dwyl.com/Dead4W/jsAesCrypt)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/22824d9dd7ae46ceb865bc2a5cded250)](https://www.codacy.com/gh/Dead4W/jsAesCrypt/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Dead4W/jsAesCrypt&amp;utm_campaign=Badge_Grade)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Dead4W/jsAesCrypt/badges/quality-score.png?b=main&r=1)](https://scrutinizer-ci.com/g/Dead4W/jsAesCrypt/?branch=main)

![Code size](https://img.shields.io/github/languages/code-size/dead4w/jsaescrypt.svg)
![Lines of Code](https://tokei.rs/b1/github/dead4w/jsaescrypt?category=code)

------------------------
jsAesCrypt is a Javascript file-encryption library and script that uses AES256-CBC to encrypt/decrypt files and binary files.

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
    - enc-utf16.js
 - enc-uint8array.js (Custom Uint8Array encoding)

Library usage example
------------------------
Here is an example showing encryption and decryption of a file:

```javascript
// Init aesCrypt library
const aes = aesCrypt;

let fileSecret = document.getElementById("fileSecret").files[0];

let password = "foopassword"

// encryption/decryption

// encrypt typed array (Uint8Array)
aes.encrypt(fileSecret, password).then((encrypted) => {
  console.log(encrypted);
});

let fileEncrypted = document.getElementById("fileEncrypted").files[0];

// decrypt typed array (Uint8Array)
aes.decrypt(fileEncrypted, password).then((decrypted) => {

  // transform Uint8Array to Latin1 string
  let secret = aes.utils.bytes2str(decrypted);
  
  console.log(secret);
});
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
