/** global: CryptoJS */

(function () {
    // Shortcuts
    const C = CryptoJS;
    const C_lib = C.lib;
    const WordArray = C_lib.WordArray;
    const C_enc = C.enc;

    /**
     * Uint8Arr encoding strategy.
     */
    const Uint8Arr = C_enc.Uint8Arr = {


        /**
         * Converts a word array to a Uint8Arr.
         *
         * @param {string} wordArray The word array.
         *
         * @return The Uint8Array.
         *
         * @static
         *
         * @example
         *
         *     var Uint8Arr = CryptoJS.enc.Uint8Arr.decode(wordArray);
         */
        decode: function (wordArray) {
            // Shortcuts
            const words = wordArray.words;
            const sigBytes = wordArray.sigBytes;

            // Convert
            const intArray = [];
            for (let i = 0; i < sigBytes; i ++) {
                const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                intArray.push(bite);
            }

            return new Uint8Array(intArray)
        },

        /**
         * Converts a Uint8Arr to a word array.
         *
         * @param {string} arrTyped The Uint8Array.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Uint8Arr.parse(arrTyped);
         */
        parse: function (uint8arr) {
            // Shortcut
            const words = [];
            const arrLength = uint8arr.length;

            // Convert
            for (let i = 0; i < arrLength; i ++) {
                words[i * 2 >>> 3] |= uint8arr[i] << (24 - (i * 2 % 8) * 4);
            }

            return new WordArray.init(words, arrLength);
        },
    };
}());