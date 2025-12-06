/**
 * NexusCore API Monitor Script
 *
 * Monitors Windows API calls for malware behavior analysis.
 * Categories: File, Registry, Network, Memory, Process
 *
 * Usage: Inject with api_monitor tool, specifying categories to monitor
 */

'use strict';

// Configuration (can be overridden by injector)
var config = {
    categories: ['file', 'registry', 'network', 'memory', 'process'],
    maxStringLength: 256,
    captureStackTrace: false
};

// Parse config from global variable if set
if (typeof monitorConfig !== 'undefined') {
    config = Object.assign(config, monitorConfig);
}

// Utility functions
function readWideString(ptr, maxLen) {
    if (ptr.isNull()) return null;
    try {
        return ptr.readUtf16String(maxLen || config.maxStringLength);
    } catch (e) {
        return null;
    }
}

function readAnsiString(ptr, maxLen) {
    if (ptr.isNull()) return null;
    try {
        return ptr.readAnsiString(maxLen || config.maxStringLength);
    } catch (e) {
        return null;
    }
}

function getTimestamp() {
    return new Date().toISOString();
}

function sendEvent(category, api, data) {
    send({
        type: 'api_call',
        timestamp: getTimestamp(),
        category: category,
        api: api,
        data: data
    });
}

// ============================================
// FILE OPERATIONS
// ============================================

if (config.categories.includes('file')) {

    // CreateFileW
    var pCreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
    if (pCreateFileW) {
        Interceptor.attach(pCreateFileW, {
            onEnter: function(args) {
                this.fileName = readWideString(args[0]);
                this.access = args[1].toInt32();
                this.creation = args[4].toInt32();
            },
            onLeave: function(retval) {
                var accessStr = [];
                if (this.access & 0x80000000) accessStr.push('READ');
                if (this.access & 0x40000000) accessStr.push('WRITE');
                if (this.access & 0x10000000) accessStr.push('EXECUTE');

                sendEvent('file', 'CreateFileW', {
                    fileName: this.fileName,
                    access: accessStr.join('|') || 'NONE',
                    handle: retval.toString()
                });
            }
        });
    }

    // WriteFile
    var pWriteFile = Module.findExportByName('kernel32.dll', 'WriteFile');
    if (pWriteFile) {
        Interceptor.attach(pWriteFile, {
            onEnter: function(args) {
                this.handle = args[0];
                this.size = args[2].toInt32();
                // Capture first 64 bytes of data
                try {
                    this.preview = args[1].readByteArray(Math.min(64, this.size));
                } catch (e) {
                    this.preview = null;
                }
            },
            onLeave: function(retval) {
                sendEvent('file', 'WriteFile', {
                    handle: this.handle.toString(),
                    bytesWritten: this.size,
                    preview: this.preview ? Array.from(new Uint8Array(this.preview)).map(b => b.toString(16).padStart(2, '0')).join(' ') : null,
                    success: retval.toInt32() !== 0
                });
            }
        });
    }

    // DeleteFileW
    var pDeleteFileW = Module.findExportByName('kernel32.dll', 'DeleteFileW');
    if (pDeleteFileW) {
        Interceptor.attach(pDeleteFileW, {
            onEnter: function(args) {
                this.fileName = readWideString(args[0]);
            },
            onLeave: function(retval) {
                sendEvent('file', 'DeleteFileW', {
                    fileName: this.fileName,
                    success: retval.toInt32() !== 0
                });
            }
        });
    }

    // CopyFileW
    var pCopyFileW = Module.findExportByName('kernel32.dll', 'CopyFileW');
    if (pCopyFileW) {
        Interceptor.attach(pCopyFileW, {
            onEnter: function(args) {
                this.source = readWideString(args[0]);
                this.dest = readWideString(args[1]);
            },
            onLeave: function(retval) {
                sendEvent('file', 'CopyFileW', {
                    source: this.source,
                    destination: this.dest,
                    success: retval.toInt32() !== 0
                });
            }
        });
    }

    // MoveFileW
    var pMoveFileW = Module.findExportByName('kernel32.dll', 'MoveFileW');
    if (pMoveFileW) {
        Interceptor.attach(pMoveFileW, {
            onEnter: function(args) {
                this.source = readWideString(args[0]);
                this.dest = readWideString(args[1]);
            },
            onLeave: function(retval) {
                sendEvent('file', 'MoveFileW', {
                    source: this.source,
                    destination: this.dest,
                    success: retval.toInt32() !== 0
                });
            }
        });
    }

    send({ type: 'hook', category: 'file', status: 'installed', apis: ['CreateFileW', 'WriteFile', 'DeleteFileW', 'CopyFileW', 'MoveFileW'] });
}

// ============================================
// REGISTRY OPERATIONS
// ============================================

if (config.categories.includes('registry')) {

    // RegCreateKeyExW
    var pRegCreateKeyExW = Module.findExportByName('advapi32.dll', 'RegCreateKeyExW');
    if (pRegCreateKeyExW) {
        Interceptor.attach(pRegCreateKeyExW, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.subKey = readWideString(args[1]);
            },
            onLeave: function(retval) {
                sendEvent('registry', 'RegCreateKeyExW', {
                    hKey: this.hKey.toString(),
                    subKey: this.subKey,
                    result: retval.toInt32()
                });
            }
        });
    }

    // RegSetValueExW
    var pRegSetValueExW = Module.findExportByName('advapi32.dll', 'RegSetValueExW');
    if (pRegSetValueExW) {
        Interceptor.attach(pRegSetValueExW, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.valueName = readWideString(args[1]);
                this.type = args[3].toInt32();
                this.dataSize = args[5].toInt32();

                // Try to read value data
                try {
                    if (this.type === 1 || this.type === 2) { // REG_SZ, REG_EXPAND_SZ
                        this.data = readWideString(args[4], this.dataSize);
                    } else if (this.type === 4) { // REG_DWORD
                        this.data = args[4].readU32();
                    } else {
                        this.data = args[4].readByteArray(Math.min(64, this.dataSize));
                        this.data = Array.from(new Uint8Array(this.data)).map(b => b.toString(16).padStart(2, '0')).join(' ');
                    }
                } catch (e) {
                    this.data = null;
                }
            },
            onLeave: function(retval) {
                var typeNames = { 0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD', 7: 'REG_MULTI_SZ' };
                sendEvent('registry', 'RegSetValueExW', {
                    hKey: this.hKey.toString(),
                    valueName: this.valueName,
                    type: typeNames[this.type] || this.type,
                    data: this.data,
                    result: retval.toInt32()
                });
            }
        });
    }

    // RegDeleteKeyW
    var pRegDeleteKeyW = Module.findExportByName('advapi32.dll', 'RegDeleteKeyW');
    if (pRegDeleteKeyW) {
        Interceptor.attach(pRegDeleteKeyW, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.subKey = readWideString(args[1]);
            },
            onLeave: function(retval) {
                sendEvent('registry', 'RegDeleteKeyW', {
                    hKey: this.hKey.toString(),
                    subKey: this.subKey,
                    result: retval.toInt32()
                });
            }
        });
    }

    // RegDeleteValueW
    var pRegDeleteValueW = Module.findExportByName('advapi32.dll', 'RegDeleteValueW');
    if (pRegDeleteValueW) {
        Interceptor.attach(pRegDeleteValueW, {
            onEnter: function(args) {
                this.hKey = args[0];
                this.valueName = readWideString(args[1]);
            },
            onLeave: function(retval) {
                sendEvent('registry', 'RegDeleteValueW', {
                    hKey: this.hKey.toString(),
                    valueName: this.valueName,
                    result: retval.toInt32()
                });
            }
        });
    }

    send({ type: 'hook', category: 'registry', status: 'installed', apis: ['RegCreateKeyExW', 'RegSetValueExW', 'RegDeleteKeyW', 'RegDeleteValueW'] });
}

// ============================================
// NETWORK OPERATIONS
// ============================================

if (config.categories.includes('network')) {

    // connect
    var pConnect = Module.findExportByName('ws2_32.dll', 'connect');
    if (pConnect) {
        Interceptor.attach(pConnect, {
            onEnter: function(args) {
                this.socket = args[0];
                var sockaddr = args[1];
                var family = sockaddr.readU16();

                if (family === 2) { // AF_INET
                    var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                    var ip = sockaddr.add(4).readU8() + '.' +
                             sockaddr.add(5).readU8() + '.' +
                             sockaddr.add(6).readU8() + '.' +
                             sockaddr.add(7).readU8();
                    this.address = ip + ':' + port;
                    this.family = 'IPv4';
                } else {
                    this.address = 'unknown';
                    this.family = family;
                }
            },
            onLeave: function(retval) {
                sendEvent('network', 'connect', {
                    socket: this.socket.toString(),
                    address: this.address,
                    family: this.family,
                    result: retval.toInt32()
                });
            }
        });
    }

    // send
    var pSend = Module.findExportByName('ws2_32.dll', 'send');
    if (pSend) {
        Interceptor.attach(pSend, {
            onEnter: function(args) {
                this.socket = args[0];
                this.len = args[2].toInt32();
                try {
                    this.preview = args[1].readByteArray(Math.min(64, this.len));
                } catch (e) {
                    this.preview = null;
                }
            },
            onLeave: function(retval) {
                sendEvent('network', 'send', {
                    socket: this.socket.toString(),
                    length: this.len,
                    bytesSent: retval.toInt32(),
                    preview: this.preview ? Array.from(new Uint8Array(this.preview)).map(b => b.toString(16).padStart(2, '0')).join(' ') : null
                });
            }
        });
    }

    // recv
    var pRecv = Module.findExportByName('ws2_32.dll', 'recv');
    if (pRecv) {
        Interceptor.attach(pRecv, {
            onEnter: function(args) {
                this.socket = args[0];
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function(retval) {
                var bytesReceived = retval.toInt32();
                var preview = null;
                if (bytesReceived > 0) {
                    try {
                        preview = this.buf.readByteArray(Math.min(64, bytesReceived));
                        preview = Array.from(new Uint8Array(preview)).map(b => b.toString(16).padStart(2, '0')).join(' ');
                    } catch (e) {}
                }
                sendEvent('network', 'recv', {
                    socket: this.socket.toString(),
                    bytesReceived: bytesReceived,
                    preview: preview
                });
            }
        });
    }

    // WSAConnect (for async connections)
    var pWSAConnect = Module.findExportByName('ws2_32.dll', 'WSAConnect');
    if (pWSAConnect) {
        Interceptor.attach(pWSAConnect, {
            onEnter: function(args) {
                this.socket = args[0];
                var sockaddr = args[1];
                var family = sockaddr.readU16();

                if (family === 2) { // AF_INET
                    var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                    var ip = sockaddr.add(4).readU8() + '.' +
                             sockaddr.add(5).readU8() + '.' +
                             sockaddr.add(6).readU8() + '.' +
                             sockaddr.add(7).readU8();
                    this.address = ip + ':' + port;
                } else {
                    this.address = 'unknown';
                }
            },
            onLeave: function(retval) {
                sendEvent('network', 'WSAConnect', {
                    socket: this.socket.toString(),
                    address: this.address,
                    result: retval.toInt32()
                });
            }
        });
    }

    // getaddrinfo (DNS resolution)
    var pGetAddrInfoW = Module.findExportByName('ws2_32.dll', 'GetAddrInfoW');
    if (pGetAddrInfoW) {
        Interceptor.attach(pGetAddrInfoW, {
            onEnter: function(args) {
                this.nodeName = readWideString(args[0]);
                this.serviceName = readWideString(args[1]);
            },
            onLeave: function(retval) {
                sendEvent('network', 'GetAddrInfoW', {
                    hostname: this.nodeName,
                    service: this.serviceName,
                    result: retval.toInt32()
                });
            }
        });
    }

    send({ type: 'hook', category: 'network', status: 'installed', apis: ['connect', 'send', 'recv', 'WSAConnect', 'GetAddrInfoW'] });
}

// ============================================
// MEMORY OPERATIONS
// ============================================

if (config.categories.includes('memory')) {

    // VirtualAlloc
    var pVirtualAlloc = Module.findExportByName('kernel32.dll', 'VirtualAlloc');
    if (pVirtualAlloc) {
        Interceptor.attach(pVirtualAlloc, {
            onEnter: function(args) {
                this.address = args[0];
                this.size = args[1].toInt32();
                this.allocType = args[2].toInt32();
                this.protect = args[3].toInt32();
            },
            onLeave: function(retval) {
                var protectFlags = [];
                if (this.protect & 0x10) protectFlags.push('EXECUTE');
                if (this.protect & 0x20) protectFlags.push('EXECUTE_READ');
                if (this.protect & 0x40) protectFlags.push('EXECUTE_READWRITE');
                if (this.protect & 0x02) protectFlags.push('READONLY');
                if (this.protect & 0x04) protectFlags.push('READWRITE');

                sendEvent('memory', 'VirtualAlloc', {
                    requestedAddress: this.address.toString(),
                    allocatedAddress: retval.toString(),
                    size: this.size,
                    protection: protectFlags.join('|') || this.protect.toString(16)
                });
            }
        });
    }

    // VirtualProtect
    var pVirtualProtect = Module.findExportByName('kernel32.dll', 'VirtualProtect');
    if (pVirtualProtect) {
        Interceptor.attach(pVirtualProtect, {
            onEnter: function(args) {
                this.address = args[0];
                this.size = args[1].toInt32();
                this.newProtect = args[2].toInt32();
            },
            onLeave: function(retval) {
                var protectFlags = [];
                if (this.newProtect & 0x10) protectFlags.push('EXECUTE');
                if (this.newProtect & 0x20) protectFlags.push('EXECUTE_READ');
                if (this.newProtect & 0x40) protectFlags.push('EXECUTE_READWRITE');
                if (this.newProtect & 0x02) protectFlags.push('READONLY');
                if (this.newProtect & 0x04) protectFlags.push('READWRITE');

                sendEvent('memory', 'VirtualProtect', {
                    address: this.address.toString(),
                    size: this.size,
                    newProtection: protectFlags.join('|') || this.newProtect.toString(16),
                    success: retval.toInt32() !== 0
                });
            }
        });
    }

    // VirtualAllocEx (remote allocation)
    var pVirtualAllocEx = Module.findExportByName('kernel32.dll', 'VirtualAllocEx');
    if (pVirtualAllocEx) {
        Interceptor.attach(pVirtualAllocEx, {
            onEnter: function(args) {
                this.process = args[0];
                this.address = args[1];
                this.size = args[2].toInt32();
                this.protect = args[4].toInt32();
            },
            onLeave: function(retval) {
                sendEvent('memory', 'VirtualAllocEx', {
                    processHandle: this.process.toString(),
                    allocatedAddress: retval.toString(),
                    size: this.size,
                    protection: this.protect.toString(16),
                    isRemote: true
                });
            }
        });
    }

    send({ type: 'hook', category: 'memory', status: 'installed', apis: ['VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx'] });
}

// ============================================
// PROCESS OPERATIONS
// ============================================

if (config.categories.includes('process')) {

    // CreateProcessW
    var pCreateProcessW = Module.findExportByName('kernel32.dll', 'CreateProcessW');
    if (pCreateProcessW) {
        Interceptor.attach(pCreateProcessW, {
            onEnter: function(args) {
                this.appName = readWideString(args[0]);
                this.cmdLine = readWideString(args[1]);
                this.creationFlags = args[5].toInt32();
            },
            onLeave: function(retval) {
                var flags = [];
                if (this.creationFlags & 0x00000004) flags.push('CREATE_SUSPENDED');
                if (this.creationFlags & 0x00000008) flags.push('DETACHED_PROCESS');
                if (this.creationFlags & 0x00000010) flags.push('CREATE_NEW_CONSOLE');
                if (this.creationFlags & 0x08000000) flags.push('CREATE_NO_WINDOW');

                sendEvent('process', 'CreateProcessW', {
                    application: this.appName,
                    commandLine: this.cmdLine,
                    flags: flags.join('|') || 'NONE',
                    success: retval.toInt32() !== 0
                });
            }
        });
    }

    // CreateRemoteThread
    var pCreateRemoteThread = Module.findExportByName('kernel32.dll', 'CreateRemoteThread');
    if (pCreateRemoteThread) {
        Interceptor.attach(pCreateRemoteThread, {
            onEnter: function(args) {
                this.process = args[0];
                this.startAddress = args[3];
                this.parameter = args[4];
            },
            onLeave: function(retval) {
                sendEvent('process', 'CreateRemoteThread', {
                    processHandle: this.process.toString(),
                    startAddress: this.startAddress.toString(),
                    parameter: this.parameter.toString(),
                    threadHandle: retval.toString(),
                    suspicious: true
                });
            }
        });
    }

    // OpenProcess
    var pOpenProcess = Module.findExportByName('kernel32.dll', 'OpenProcess');
    if (pOpenProcess) {
        Interceptor.attach(pOpenProcess, {
            onEnter: function(args) {
                this.access = args[0].toInt32();
                this.pid = args[2].toInt32();
            },
            onLeave: function(retval) {
                var accessFlags = [];
                if (this.access & 0x0010) accessFlags.push('VM_READ');
                if (this.access & 0x0020) accessFlags.push('VM_WRITE');
                if (this.access & 0x0008) accessFlags.push('VM_OPERATION');
                if (this.access & 0x0002) accessFlags.push('CREATE_THREAD');
                if (this.access & 0x001F0FFF) accessFlags.push('ALL_ACCESS');

                sendEvent('process', 'OpenProcess', {
                    targetPid: this.pid,
                    accessRights: accessFlags.join('|') || this.access.toString(16),
                    handle: retval.toString()
                });
            }
        });
    }

    // WriteProcessMemory
    var pWriteProcessMemory = Module.findExportByName('kernel32.dll', 'WriteProcessMemory');
    if (pWriteProcessMemory) {
        Interceptor.attach(pWriteProcessMemory, {
            onEnter: function(args) {
                this.process = args[0];
                this.address = args[1];
                this.size = args[3].toInt32();
                try {
                    this.preview = args[2].readByteArray(Math.min(32, this.size));
                } catch (e) {
                    this.preview = null;
                }
            },
            onLeave: function(retval) {
                sendEvent('process', 'WriteProcessMemory', {
                    processHandle: this.process.toString(),
                    address: this.address.toString(),
                    size: this.size,
                    preview: this.preview ? Array.from(new Uint8Array(this.preview)).map(b => b.toString(16).padStart(2, '0')).join(' ') : null,
                    success: retval.toInt32() !== 0,
                    suspicious: true
                });
            }
        });
    }

    // NtCreateThreadEx (for stealthier thread creation)
    var pNtCreateThreadEx = Module.findExportByName('ntdll.dll', 'NtCreateThreadEx');
    if (pNtCreateThreadEx) {
        Interceptor.attach(pNtCreateThreadEx, {
            onEnter: function(args) {
                this.process = args[3];
                this.startAddress = args[4];
            },
            onLeave: function(retval) {
                sendEvent('process', 'NtCreateThreadEx', {
                    processHandle: this.process.toString(),
                    startAddress: this.startAddress.toString(),
                    result: retval.toInt32(),
                    suspicious: true
                });
            }
        });
    }

    send({ type: 'hook', category: 'process', status: 'installed', apis: ['CreateProcessW', 'CreateRemoteThread', 'OpenProcess', 'WriteProcessMemory', 'NtCreateThreadEx'] });
}

// ============================================
// Initialization Complete
// ============================================

send({
    type: 'init',
    message: 'API Monitor loaded successfully',
    categories: config.categories
});
