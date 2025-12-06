/*
    NexusCore API Monitor Script
    Monitors Windows API calls based on configured categories.
    Categories: file, registry, network, memory, process
    
    Configuration is passed via `monitorConfig` object.
*/

(function () {
    'use strict';

    var config = typeof monitorConfig !== 'undefined' ? monitorConfig : { categories: ['file', 'registry', 'network', 'memory', 'process'] };
    var categories = config.categories || [];

    // Batch buffering for performance
    var eventQueue = [];
    var lastFlush = Date.now();
    var BATCH_SIZE = 20;
    var FLUSH_INTERVAL = 500;

    function flushEvents() {
        if (eventQueue.length > 0) {
            send({
                type: 'api_batch',
                count: eventQueue.length,
                events: eventQueue
            });
            eventQueue = [];
            lastFlush = Date.now();
        }
    }

    // Periodic flush timer
    setInterval(flushEvents, FLUSH_INTERVAL);

    function log(api, args) {
        eventQueue.push({
            api: api,
            args: args,
            timestamp: Date.now(),
            tid: Process.getCurrentThreadId()
        });

        // Flush if batch full
        if (eventQueue.length >= BATCH_SIZE) {
            flushEvents();
        }
    }

    // ===================== FILE OPERATIONS =====================
    if (categories.indexOf('file') !== -1) {
        // CreateFileW
        var CreateFileW = Module.getExportByName('kernel32.dll', 'CreateFileW');
        if (CreateFileW) {
            Interceptor.attach(CreateFileW, {
                onEnter: function (args) {
                    this.filename = args[0].readUtf16String();
                    this.access = args[1].toInt32();
                },
                onLeave: function (retval) {
                    log('CreateFileW', {
                        filename: this.filename,
                        access: this.access,
                        handle: retval.toString()
                    });
                }
            });
        }

        // WriteFile
        var WriteFile = Module.getExportByName('kernel32.dll', 'WriteFile');
        if (WriteFile) {
            Interceptor.attach(WriteFile, {
                onEnter: function (args) {
                    this.handle = args[0];
                    this.size = args[2].toInt32();
                },
                onLeave: function (retval) {
                    log('WriteFile', {
                        handle: this.handle.toString(),
                        size: this.size,
                        success: retval.toInt32() !== 0
                    });
                }
            });
        }

        // DeleteFileW
        var DeleteFileW = Module.getExportByName('kernel32.dll', 'DeleteFileW');
        if (DeleteFileW) {
            Interceptor.attach(DeleteFileW, {
                onEnter: function (args) {
                    this.filename = args[0].readUtf16String();
                },
                onLeave: function (retval) {
                    log('DeleteFileW', {
                        filename: this.filename,
                        success: retval.toInt32() !== 0
                    });
                }
            });
        }
    }

    // ===================== REGISTRY OPERATIONS =====================
    if (categories.indexOf('registry') !== -1) {
        // RegCreateKeyExW
        var RegCreateKeyExW = Module.getExportByName('advapi32.dll', 'RegCreateKeyExW');
        if (RegCreateKeyExW) {
            Interceptor.attach(RegCreateKeyExW, {
                onEnter: function (args) {
                    this.hKey = args[0];
                    this.subKey = args[1].readUtf16String();
                },
                onLeave: function (retval) {
                    log('RegCreateKeyExW', {
                        hKey: this.hKey.toString(),
                        subKey: this.subKey,
                        result: retval.toInt32()
                    });
                }
            });
        }

        // RegSetValueExW
        var RegSetValueExW = Module.getExportByName('advapi32.dll', 'RegSetValueExW');
        if (RegSetValueExW) {
            Interceptor.attach(RegSetValueExW, {
                onEnter: function (args) {
                    this.hKey = args[0];
                    this.valueName = args[1].readUtf16String();
                    this.type = args[3].toInt32();
                    this.dataSize = args[5].toInt32();
                },
                onLeave: function (retval) {
                    log('RegSetValueExW', {
                        hKey: this.hKey.toString(),
                        valueName: this.valueName,
                        type: this.type,
                        dataSize: this.dataSize,
                        result: retval.toInt32()
                    });
                }
            });
        }

        // RegDeleteKeyW
        var RegDeleteKeyW = Module.getExportByName('advapi32.dll', 'RegDeleteKeyW');
        if (RegDeleteKeyW) {
            Interceptor.attach(RegDeleteKeyW, {
                onEnter: function (args) {
                    this.hKey = args[0];
                    this.subKey = args[1].readUtf16String();
                },
                onLeave: function (retval) {
                    log('RegDeleteKeyW', {
                        hKey: this.hKey.toString(),
                        subKey: this.subKey,
                        result: retval.toInt32()
                    });
                }
            });
        }
    }

    // ===================== NETWORK OPERATIONS =====================
    if (categories.indexOf('network') !== -1) {
        // connect (ws2_32.dll)
        var connect = Module.getExportByName('ws2_32.dll', 'connect');
        if (connect) {
            Interceptor.attach(connect, {
                onEnter: function (args) {
                    this.socket = args[0];
                    var sockaddr = args[1];
                    var family = sockaddr.readU16();
                    if (family === 2) { // AF_INET
                        var port = sockaddr.add(2).readU16();
                        port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF); // ntohs
                        var ip = sockaddr.add(4).readByteArray(4);
                        var ipStr = new Uint8Array(ip).join('.');
                        this.addr = ipStr + ':' + port;
                    } else {
                        this.addr = 'AF=' + family;
                    }
                },
                onLeave: function (retval) {
                    log('connect', {
                        socket: this.socket.toString(),
                        address: this.addr,
                        result: retval.toInt32()
                    });
                }
            });
        }

        // send
        var send_fn = Module.getExportByName('ws2_32.dll', 'send');
        if (send_fn) {
            Interceptor.attach(send_fn, {
                onEnter: function (args) {
                    this.socket = args[0];
                    this.len = args[2].toInt32();
                },
                onLeave: function (retval) {
                    log('send', {
                        socket: this.socket.toString(),
                        length: this.len,
                        sent: retval.toInt32()
                    });
                }
            });
        }

        // recv
        var recv_fn = Module.getExportByName('ws2_32.dll', 'recv');
        if (recv_fn) {
            Interceptor.attach(recv_fn, {
                onEnter: function (args) {
                    this.socket = args[0];
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                },
                onLeave: function (retval) {
                    log('recv', {
                        socket: this.socket.toString(),
                        requestedLen: this.len,
                        received: retval.toInt32()
                    });
                }
            });
        }

        // GetAddrInfoW (DNS)
        var GetAddrInfoW = Module.getExportByName('ws2_32.dll', 'GetAddrInfoW');
        if (GetAddrInfoW) {
            Interceptor.attach(GetAddrInfoW, {
                onEnter: function (args) {
                    this.nodeName = args[0].readUtf16String();
                },
                onLeave: function (retval) {
                    log('GetAddrInfoW', {
                        hostname: this.nodeName,
                        result: retval.toInt32()
                    });
                }
            });
        }
    }

    // ===================== MEMORY OPERATIONS =====================
    if (categories.indexOf('memory') !== -1) {
        // VirtualAlloc
        var VirtualAlloc = Module.getExportByName('kernel32.dll', 'VirtualAlloc');
        if (VirtualAlloc) {
            Interceptor.attach(VirtualAlloc, {
                onEnter: function (args) {
                    this.size = args[1].toInt32();
                    this.protect = args[3].toInt32();
                },
                onLeave: function (retval) {
                    log('VirtualAlloc', {
                        address: retval.toString(),
                        size: this.size,
                        protection: this.protect
                    });
                }
            });
        }

        // VirtualProtect
        var VirtualProtect = Module.getExportByName('kernel32.dll', 'VirtualProtect');
        if (VirtualProtect) {
            Interceptor.attach(VirtualProtect, {
                onEnter: function (args) {
                    this.addr = args[0];
                    this.size = args[1].toInt32();
                    this.newProtect = args[2].toInt32();
                },
                onLeave: function (retval) {
                    log('VirtualProtect', {
                        address: this.addr.toString(),
                        size: this.size,
                        newProtection: this.newProtect,
                        success: retval.toInt32() !== 0
                    });
                }
            });
        }

        // VirtualAllocEx (Cross-process)
        var VirtualAllocEx = Module.getExportByName('kernel32.dll', 'VirtualAllocEx');
        if (VirtualAllocEx) {
            Interceptor.attach(VirtualAllocEx, {
                onEnter: function (args) {
                    this.hProcess = args[0];
                    this.size = args[2].toInt32();
                    this.protect = args[4].toInt32();
                },
                onLeave: function (retval) {
                    log('VirtualAllocEx', {
                        targetProcess: this.hProcess.toString(),
                        address: retval.toString(),
                        size: this.size,
                        protection: this.protect
                    });
                }
            });
        }

        // WriteProcessMemory
        var WriteProcessMemory = Module.getExportByName('kernel32.dll', 'WriteProcessMemory');
        if (WriteProcessMemory) {
            Interceptor.attach(WriteProcessMemory, {
                onEnter: function (args) {
                    this.hProcess = args[0];
                    this.baseAddr = args[1];
                    this.size = args[3].toInt32();
                },
                onLeave: function (retval) {
                    log('WriteProcessMemory', {
                        targetProcess: this.hProcess.toString(),
                        address: this.baseAddr.toString(),
                        size: this.size,
                        success: retval.toInt32() !== 0
                    });
                }
            });
        }
    }

    // ===================== PROCESS OPERATIONS =====================
    if (categories.indexOf('process') !== -1) {
        // CreateProcessW
        var CreateProcessW = Module.getExportByName('kernel32.dll', 'CreateProcessW');
        if (CreateProcessW) {
            Interceptor.attach(CreateProcessW, {
                onEnter: function (args) {
                    this.appName = args[0].isNull() ? null : args[0].readUtf16String();
                    this.cmdLine = args[1].isNull() ? null : args[1].readUtf16String();
                },
                onLeave: function (retval) {
                    log('CreateProcessW', {
                        applicationName: this.appName,
                        commandLine: this.cmdLine,
                        success: retval.toInt32() !== 0
                    });
                }
            });
        }

        // OpenProcess
        var OpenProcess = Module.getExportByName('kernel32.dll', 'OpenProcess');
        if (OpenProcess) {
            Interceptor.attach(OpenProcess, {
                onEnter: function (args) {
                    this.desiredAccess = args[0].toInt32();
                    this.pid = args[2].toInt32();
                },
                onLeave: function (retval) {
                    log('OpenProcess', {
                        pid: this.pid,
                        desiredAccess: this.desiredAccess,
                        handle: retval.toString()
                    });
                }
            });
        }

        // CreateRemoteThread
        var CreateRemoteThread = Module.getExportByName('kernel32.dll', 'CreateRemoteThread');
        if (CreateRemoteThread) {
            Interceptor.attach(CreateRemoteThread, {
                onEnter: function (args) {
                    this.hProcess = args[0];
                    this.startAddr = args[3];
                },
                onLeave: function (retval) {
                    log('CreateRemoteThread', {
                        targetProcess: this.hProcess.toString(),
                        startAddress: this.startAddr.toString(),
                        threadHandle: retval.toString()
                    });
                }
            });
        }

        // NtCreateThreadEx (ntdll)
        var NtCreateThreadEx = Module.getExportByName('ntdll.dll', 'NtCreateThreadEx');
        if (NtCreateThreadEx) {
            Interceptor.attach(NtCreateThreadEx, {
                onEnter: function (args) {
                    this.processHandle = args[3];
                    this.startRoutine = args[4];
                },
                onLeave: function (retval) {
                    log('NtCreateThreadEx', {
                        processHandle: this.processHandle.toString(),
                        startRoutine: this.startRoutine.toString(),
                        status: retval.toInt32()
                    });
                }
            });
        }
    }

    console.log('[NexusCore] API Monitor loaded. Categories: ' + categories.join(', '));
})();
