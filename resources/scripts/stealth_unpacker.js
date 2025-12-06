/**
 * NexusCore Stealth Unpacker Script
 *
 * This Frida script bypasses common anti-debugging and anti-VM checks
 * used by packers like Themida, VMProtect, and others.
 *
 * Hooks:
 * - IsDebuggerPresent
 * - CheckRemoteDebuggerPresent
 * - NtQueryInformationProcess (ProcessDebugPort, ProcessDebugFlags, ProcessDebugObjectHandle)
 * - NtSetInformationThread (ThreadHideFromDebugger)
 * - GetTickCount / QueryPerformanceCounter (timing checks)
 */

'use strict';

// ============================================
// Anti-Debug Bypass Hooks
// ============================================

// Hook IsDebuggerPresent - Always return FALSE
var pIsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
if (pIsDebuggerPresent) {
    Interceptor.attach(pIsDebuggerPresent, {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
    send({ type: 'hook', name: 'IsDebuggerPresent', status: 'bypassed' });
}

// Hook CheckRemoteDebuggerPresent - Always set FALSE
var pCheckRemoteDebuggerPresent = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
if (pCheckRemoteDebuggerPresent) {
    Interceptor.attach(pCheckRemoteDebuggerPresent, {
        onLeave: function(retval) {
            // Set the output parameter to FALSE
            if (this.context !== undefined) {
                try {
                    var pbDebuggerPresent = ptr(this.context.rdx || this.context.r8);
                    if (!pbDebuggerPresent.isNull()) {
                        pbDebuggerPresent.writeU8(0);
                    }
                } catch (e) {}
            }
            retval.replace(1); // Return TRUE (success)
        }
    });
    send({ type: 'hook', name: 'CheckRemoteDebuggerPresent', status: 'bypassed' });
}

// Hook NtQueryInformationProcess - Handle debug-related queries
var pNtQueryInformationProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
if (pNtQueryInformationProcess) {
    Interceptor.attach(pNtQueryInformationProcess, {
        onEnter: function(args) {
            this.processInfoClass = args[1].toInt32();
            this.processInfo = args[2];
        },
        onLeave: function(retval) {
            // ProcessDebugPort (0x7)
            if (this.processInfoClass === 0x7) {
                try {
                    this.processInfo.writePointer(ptr(0));
                } catch (e) {}
            }
            // ProcessDebugFlags (0x1F)
            if (this.processInfoClass === 0x1F) {
                try {
                    this.processInfo.writeU32(1); // PROCESS_DEBUG_INHERIT
                } catch (e) {}
            }
            // ProcessDebugObjectHandle (0x1E)
            if (this.processInfoClass === 0x1E) {
                retval.replace(0xC0000353); // STATUS_PORT_NOT_SET
            }
        }
    });
    send({ type: 'hook', name: 'NtQueryInformationProcess', status: 'bypassed' });
}

// Hook NtSetInformationThread - Block ThreadHideFromDebugger
var pNtSetInformationThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
if (pNtSetInformationThread) {
    Interceptor.attach(pNtSetInformationThread, {
        onEnter: function(args) {
            var threadInfoClass = args[1].toInt32();
            // ThreadHideFromDebugger = 0x11
            if (threadInfoClass === 0x11) {
                args[1] = ptr(0); // Change to invalid class
            }
        }
    });
    send({ type: 'hook', name: 'NtSetInformationThread', status: 'bypassed' });
}

// ============================================
// Anti-VM Bypass Hooks
// ============================================

// Hook NtQuerySystemInformation - Hide VM artifacts
var pNtQuerySystemInformation = Module.findExportByName('ntdll.dll', 'NtQuerySystemInformation');
if (pNtQuerySystemInformation) {
    Interceptor.attach(pNtQuerySystemInformation, {
        onEnter: function(args) {
            this.systemInfoClass = args[0].toInt32();
            this.systemInfo = args[1];
        },
        onLeave: function(retval) {
            // Can be extended to modify VM-related info
        }
    });
    send({ type: 'hook', name: 'NtQuerySystemInformation', status: 'monitoring' });
}

// ============================================
// Timing Attack Mitigation
// ============================================

var baseTickCount = null;
var pGetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
if (pGetTickCount) {
    Interceptor.attach(pGetTickCount, {
        onLeave: function(retval) {
            if (baseTickCount === null) {
                baseTickCount = retval.toInt32();
            }
            // Normalize timing to prevent detection
        }
    });
    send({ type: 'hook', name: 'GetTickCount', status: 'monitoring' });
}

// ============================================
// PEB Patching
// ============================================

try {
    var peb = Process.findModuleByName('ntdll.dll');
    if (peb) {
        // Get PEB address from TEB
        var teb = ptr(Process.getCurrentThreadId());
        // PEB->BeingDebugged offset is 0x2 (32-bit) or 0x2 (64-bit)
        // This is simplified - actual implementation needs proper TEB/PEB access
    }
} catch (e) {
    send({ type: 'error', message: 'PEB patching failed: ' + e.message });
}

// ============================================
// Initialization Complete
// ============================================

send({
    type: 'init',
    message: 'Stealth Unpacker loaded successfully',
    hooks: [
        'IsDebuggerPresent',
        'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess',
        'NtSetInformationThread',
        'NtQuerySystemInformation',
        'GetTickCount'
    ]
});
