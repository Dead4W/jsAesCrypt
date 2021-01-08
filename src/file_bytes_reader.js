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