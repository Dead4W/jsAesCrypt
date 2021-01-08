/** global: binaryStream */

/**
 * binary array stream object
 *
 *
 * @return The binaryStream object.
 *
 * @static
 *
 * @example
 *     var binaryStream = binaryStream([1,2,3]);
 *     binaryStream.appendBytes([4,5,6]);
 *     binaryStream.appendBytes("\x07\x08\x09");
 *     console.log(binaryStream.finalize()) // returns Uint8Array [1,2,3,4,5,6,7,8,9]
 *
 * @param arr origin array
 */
const binaryStream = function(arr = []) {
    let _data = new Uint8Array(arr);

    function appendBytes(input) {
        let tmp;

        if (typeof (input) == "number") {
            let hex = input.toString(16);
            tmp = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
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
        appendBytes,
        finalize,
        get,
        getLength,
    }
}