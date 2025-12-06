/*
    NexusCore Crypto Hook
    Captures encryption/decryption operations including keys and plaintext.
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
            for (var i = 0; i < arr.length && i < 256; i++) {
                hex += ('0' + arr[i].toString(16)).slice(-2);
            }
            if (arr.length > 256) hex += '...';
            return hex;
        } catch (e) {
            return null;
        }
    }

    // ===================== CryptoAPI (advapi32/crypt32) =====================

    // CryptEncrypt
    var CryptEncrypt = Module.getExportByName('advapi32.dll', 'CryptEncrypt');
    if (CryptEncrypt) {
        Interceptor.attach(CryptEncrypt, {
            onEnter: function (args) {
                this.hKey = args[0];
                this.pbData = args[4];
                this.pdwDataLen = args[5];
                // Read data length
                this.dataLen = this.pdwDataLen.readU32();
                this.plaintext = hexify(this.pbData, this.dataLen);
            },
            onLeave: function (retval) {
                var newLen = this.pdwDataLen.readU32();
                send({
                    type: 'crypto_operation',
                    api: 'CryptEncrypt',
                    direction: 'encrypt',
                    hKey: this.hKey.toString(),
                    plaintextLen: this.dataLen,
                    ciphertextLen: newLen,
                    plaintext: this.plaintext,
                    ciphertext: hexify(this.pbData, newLen),
                    success: retval.toInt32() !== 0
                });
            }
        });
    }

    // CryptDecrypt
    var CryptDecrypt = Module.getExportByName('advapi32.dll', 'CryptDecrypt');
    if (CryptDecrypt) {
        Interceptor.attach(CryptDecrypt, {
            onEnter: function (args) {
                this.hKey = args[0];
                this.pbData = args[4];
                this.pdwDataLen = args[5];
                this.dataLen = this.pdwDataLen.readU32();
                this.ciphertext = hexify(this.pbData, this.dataLen);
            },
            onLeave: function (retval) {
                var newLen = this.pdwDataLen.readU32();
                send({
                    type: 'crypto_operation',
                    api: 'CryptDecrypt',
                    direction: 'decrypt',
                    hKey: this.hKey.toString(),
                    ciphertextLen: this.dataLen,
                    plaintextLen: newLen,
                    ciphertext: this.ciphertext,
                    plaintext: hexify(this.pbData, newLen),
                    success: retval.toInt32() !== 0
                });
            }
        });
    }

    // CryptHashData - useful for password hashing
    var CryptHashData = Module.getExportByName('advapi32.dll', 'CryptHashData');
    if (CryptHashData) {
        Interceptor.attach(CryptHashData, {
            onEnter: function (args) {
                var pbData = args[1];
                var dwDataLen = args[2].toInt32();
                send({
                    type: 'crypto_operation',
                    api: 'CryptHashData',
                    direction: 'hash_input',
                    dataLen: dwDataLen,
                    data: hexify(pbData, dwDataLen)
                });
            }
        });
    }

    // ===================== BCrypt (bcrypt.dll) =====================

    // BCryptEncrypt
    var BCryptEncrypt = Module.getExportByName('bcrypt.dll', 'BCryptEncrypt');
    if (BCryptEncrypt) {
        Interceptor.attach(BCryptEncrypt, {
            onEnter: function (args) {
                this.hKey = args[0];
                this.pbInput = args[1];
                this.cbInput = args[2].toInt32();
                this.pbOutput = args[5];
                this.plaintext = hexify(this.pbInput, this.cbInput);
            },
            onLeave: function (retval) {
                send({
                    type: 'crypto_operation',
                    api: 'BCryptEncrypt',
                    direction: 'encrypt',
                    plaintextLen: this.cbInput,
                    plaintext: this.plaintext,
                    status: retval.toInt32()
                });
            }
        });
    }

    // BCryptDecrypt
    var BCryptDecrypt = Module.getExportByName('bcrypt.dll', 'BCryptDecrypt');
    if (BCryptDecrypt) {
        Interceptor.attach(BCryptDecrypt, {
            onEnter: function (args) {
                this.hKey = args[0];
                this.pbInput = args[1];
                this.cbInput = args[2].toInt32();
                this.pbOutput = args[5];
                this.ciphertext = hexify(this.pbInput, this.cbInput);
            },
            onLeave: function (retval) {
                // Read output size from pcbResult (arg 7)
                send({
                    type: 'crypto_operation',
                    api: 'BCryptDecrypt',
                    direction: 'decrypt',
                    ciphertextLen: this.cbInput,
                    ciphertext: this.ciphertext,
                    status: retval.toInt32()
                });
            }
        });
    }

    console.log('[NexusCore] Crypto Hook loaded');
})();
