/** global: Utilities */
/** global: CryptoJS */

window.Utilities = {

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
        const arr = [];
        for (let i = 0; i < len; i ++) {
            arr.push(value);
        }
        return arr;
    },

    arrToInt: function (arr) { // buffer is an UInt8Array
        return parseInt(Array.prototype.map.call(arr, x => ('00' + x.toString(16)).slice(-2)).join(''), 16);
    },

    fileReader: function(content) {
        let _i = 0;
        let _content = content;

        function readBytes(len) {
            let block = _content.slice(_i, _i+len);
            _i += len;
            return block;
        }

        function readBytesAsString(len) {
            return Utilities.bytes_to_latin1(
                readBytes(len)
            );
        }

        function readByte() {
            return readBytes(1)[0];
        }

        function readBytesAsInt(len) {
            return Utilities.arrToInt(
                readBytes(len)
            );
        }

        function getCurrentPosition() {
            return _i;
        }

        function getLength() {
            return _content.length;
        }

        return {
            readByte: readByte,
            readBytes: readBytes,
            readBytesAsInt: readBytesAsInt,
            readBytesAsString: readBytesAsString,
            getCurrentPosition: getCurrentPosition,
            getLength: getLength,
        };
    },

    // bytes is typed array
    bytes_to_latin1: function(bytes) {
        return CryptoJS.enc.Latin1.stringify(CryptoJS.enc.Uint8Arr.parse(bytes))
    },

    encode_to_words: function (input, enc = "Latin1") {
        return CryptoJS.enc[enc].parse(input);
    },

}