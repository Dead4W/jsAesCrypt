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