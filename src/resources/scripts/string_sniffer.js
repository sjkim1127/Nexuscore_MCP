/*
    NexusCore String Sniffer
    Captures runtime-decrypted strings by monitoring memory operations.
*/

(function () {
    'use strict';

    var capturedStrings = new Set();

    function extractStrings(addr, size) {
        if (size < 4 || size > 10240) return; // Skip tiny or huge allocations

        try {
            // Try reading as ASCII
            var ascii = addr.readCString();
            if (ascii && ascii.length >= 4 && isPrintable(ascii)) {
                if (!capturedStrings.has(ascii)) {
                    capturedStrings.add(ascii);
                    send({
                        type: 'string_captured',
                        encoding: 'ascii',
                        value: ascii,
                        address: addr.toString(),
                        length: ascii.length
                    });
                }
            }

            // Try reading as UTF-16
            var utf16 = addr.readUtf16String();
            if (utf16 && utf16.length >= 4 && isPrintable(utf16)) {
                if (!capturedStrings.has(utf16)) {
                    capturedStrings.add(utf16);
                    send({
                        type: 'string_captured',
                        encoding: 'utf16',
                        value: utf16,
                        address: addr.toString(),
                        length: utf16.length
                    });
                }
            }
        } catch (e) {
            // Ignore read errors
        }
    }

    function isPrintable(str) {
        // Check if string has reasonable printable character ratio
        var printable = 0;
        for (var i = 0; i < str.length; i++) {
            var c = str.charCodeAt(i);
            if (c >= 0x20 && c < 0x7F) printable++;
        }
        return (printable / str.length) > 0.7;
    }

    // Hook VirtualAlloc - newly allocated RW memory often contains decrypted data
    var VirtualAlloc = Module.getExportByName('kernel32.dll', 'VirtualAlloc');
    if (VirtualAlloc) {
        Interceptor.attach(VirtualAlloc, {
            onEnter: function (args) {
                this.size = args[1].toInt32();
            },
            onLeave: function (retval) {
                if (!retval.isNull() && this.size > 0) {
                    // Delay check to allow data to be written
                    var addr = retval;
                    var size = this.size;
                    setTimeout(function () {
                        extractStrings(addr, size);
                    }, 100);
                }
            }
        });
    }

    // Hook HeapAlloc for smaller allocations
    var HeapAlloc = Module.getExportByName('kernel32.dll', 'HeapAlloc');
    if (HeapAlloc) {
        Interceptor.attach(HeapAlloc, {
            onEnter: function (args) {
                this.size = args[2].toInt32();
            },
            onLeave: function (retval) {
                if (!retval.isNull() && this.size >= 16 && this.size <= 4096) {
                    var addr = retval;
                    var size = this.size;
                    setTimeout(function () {
                        extractStrings(addr, size);
                    }, 50);
                }
            }
        });
    }

    // Hook lstrcpyW - common for copying decrypted strings
    var lstrcpyW = Module.getExportByName('kernel32.dll', 'lstrcpyW');
    if (lstrcpyW) {
        Interceptor.attach(lstrcpyW, {
            onEnter: function (args) {
                this.dest = args[0];
                this.src = args[1];
            },
            onLeave: function (retval) {
                try {
                    var str = this.src.readUtf16String();
                    if (str && str.length >= 4 && !capturedStrings.has(str)) {
                        capturedStrings.add(str);
                        send({
                            type: 'string_captured',
                            encoding: 'utf16',
                            source: 'lstrcpyW',
                            value: str,
                            address: this.src.toString()
                        });
                    }
                } catch (e) { }
            }
        });
    }

    console.log('[NexusCore] String Sniffer loaded');
})();
