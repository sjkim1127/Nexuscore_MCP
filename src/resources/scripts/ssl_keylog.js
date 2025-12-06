/*
    NexusCore SSL Keylogger
    Extracts TLS session keys for Wireshark decryption.
    Format: SSLKEYLOGFILE (NSS Key Log Format)
*/

(function () {
    'use strict';

    function hexify(buf, len) {
        if (!buf || buf.isNull()) return null;
        try {
            var bytes = buf.readByteArray(len);
            if (!bytes) return null;
            var arr = new Uint8Array(bytes);
            var hex = '';
            for (var i = 0; i < arr.length; i++) {
                hex += ('0' + arr[i].toString(16)).slice(-2);
            }
            return hex;
        } catch (e) {
            return null;
        }
    }

    // ===================== Windows SChannel =====================
    // SChannel is Windows' native TLS implementation
    // We hook ncrypt.dll for key material

    var NCryptExportKey = Module.getExportByName('ncrypt.dll', 'NCryptExportKey');
    if (NCryptExportKey) {
        Interceptor.attach(NCryptExportKey, {
            onEnter: function (args) {
                this.hKey = args[0];
                this.pbOutput = args[3];
                this.pcbResult = args[5];
            },
            onLeave: function (retval) {
                if (retval.toInt32() === 0) { // Success
                    try {
                        var len = this.pcbResult.readU32();
                        if (len > 0 && len < 1024) {
                            var keyData = hexify(this.pbOutput, len);
                            if (keyData) {
                                send({
                                    type: 'ssl_key',
                                    source: 'NCryptExportKey',
                                    keyLength: len,
                                    keyData: keyData
                                });
                            }
                        }
                    } catch (e) { }
                }
            }
        });
    }

    // ===================== OpenSSL (if present) =====================
    // Many applications bundle OpenSSL

    var openssl = Module.findBaseAddress('libssl-1_1-x64.dll') ||
        Module.findBaseAddress('libssl-3-x64.dll') ||
        Module.findBaseAddress('ssleay32.dll');

    if (openssl) {
        // Hook SSL_CTX_set_keylog_callback or SSL_new
        var SSL_new = Module.getExportByName(null, 'SSL_new');
        if (SSL_new) {
            Interceptor.attach(SSL_new, {
                onLeave: function (retval) {
                    // SSL* object created, we could install keylog callback here
                    send({
                        type: 'ssl_info',
                        event: 'SSL_new',
                        ssl_ptr: retval.toString()
                    });
                }
            });
        }

        // Try to hook the keylog callback setter
        var SSL_CTX_set_keylog_callback = Module.getExportByName(null, 'SSL_CTX_set_keylog_callback');
        if (SSL_CTX_set_keylog_callback) {
            // We can intercept when the app sets its own callback
            // Or we could try to set our own
            Interceptor.attach(SSL_CTX_set_keylog_callback, {
                onEnter: function (args) {
                    this.ctx = args[0];
                    this.callback = args[1];
                },
                onLeave: function () {
                    send({
                        type: 'ssl_info',
                        event: 'keylog_callback_set',
                        ctx: this.ctx.toString()
                    });
                }
            });
        }
    }

    // ===================== WinInet / WinHTTP =====================
    // High-level HTTP APIs that use SChannel internally

    var InternetConnectW = Module.getExportByName('wininet.dll', 'InternetConnectW');
    if (InternetConnectW) {
        Interceptor.attach(InternetConnectW, {
            onEnter: function (args) {
                this.server = args[1].readUtf16String();
                this.port = args[2].toInt32();
            },
            onLeave: function (retval) {
                if (!retval.isNull()) {
                    send({
                        type: 'ssl_connection',
                        source: 'WinInet',
                        server: this.server,
                        port: this.port,
                        handle: retval.toString()
                    });
                }
            }
        });
    }

    console.log('[NexusCore] SSL Keylogger loaded');
    console.log('[*] Note: Full SSLKEYLOGFILE extraction requires deep hooking of TLS state machine.');
    console.log('[*] This script captures key export events and connection metadata.');
})();
