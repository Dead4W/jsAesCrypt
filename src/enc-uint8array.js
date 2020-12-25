(function () {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var WordArray = C_lib.WordArray;
    var C_enc = C.enc;

    /**
     * Uint8Arr encoding strategy.
     */
    var Uint8Arr = C_enc.Uint8Arr = {


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
            var words = wordArray.words;
            var sigBytes = wordArray.sigBytes;

            // Convert
            var intArray = [];
            for (var i = 0; i < sigBytes; i++) {
                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
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
            var words = [];
            var arrLength = uint8arr.length;

            // Convert
            for (var i = 0; i < arrLength; i++) {
                words[i*2 >>> 3] |= uint8arr[i] << (24 - (i*2 % 8) * 4);
            }

            return new WordArray.init(words, arrLength);
        },
    };
}());