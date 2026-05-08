//
//  CrashLogger.swift
//
//  Installs signal and NSException handlers that write a plain-text crash log
//  to Documents/crash_log.txt before the process dies.
//
//  To read it: Files app → On My iPhone → PKGExtractor → crash_log.txt
//
//  Call CrashLogger.install() once at app launch (in PKGExtractorApp.init).
//

import Foundation

enum CrashLogger {

    // Path is resolved once at install time so it's safe to use inside a signal handler.
    private static var logPath: String = ""

    static func install() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        logPath = docs.appendingPathComponent("crash_log.txt").path

        // Objective-C / Swift exceptions (e.g. NSRangeException, force-unwrap)
        NSSetUncaughtExceptionHandler { exception in
            let msg = """
=== CRASH (NSException) ===
Name:   \(exception.name.rawValue)
Reason: \(exception.reason ?? "nil")
UserInfo: \(exception.userInfo ?? [:])

Call stack:
\(exception.callStackSymbols.joined(separator: "\n"))
"""
            CrashLogger.write(msg)
        }

        // Fatal signals: SIGSEGV, SIGBUS, SIGILL, SIGABRT, SIGFPE, SIGTRAP
        let signals: [Int32] = [SIGSEGV, SIGBUS, SIGILL, SIGABRT, SIGFPE, SIGTRAP]
        for sig in signals {
            signal(sig) { signum in
                let name: String
                switch signum {
                case SIGSEGV:  name = "SIGSEGV (segmentation fault)"
                case SIGBUS:   name = "SIGBUS (bus error)"
                case SIGILL:   name = "SIGILL (illegal instruction)"
                case SIGABRT:  name = "SIGABRT (abort)"
                case SIGFPE:   name = "SIGFPE (floating point exception)"
                case SIGTRAP:  name = "SIGTRAP (trap)"
                default:       name = "signal \(signum)"
                }

                // Capture a backtrace using low-level C APIs — safe in a signal handler.
                var frames = [UnsafeMutableRawPointer?](repeating: nil, count: 128)
                let count  = backtrace(&frames, 128)
                let syms   = backtrace_symbols(&frames, count)

                var stack = ""
                if let syms {
                    for i in 0 ..< Int(count) {
                        if let s = syms[i] { stack += String(cString: s) + "\n" }
                    }
                    free(syms)
                }

                let msg = "=== CRASH (\(name)) ===\n\nBacktrace:\n\(stack)"
                CrashLogger.write(msg)

                // Re-raise so the OS gets the real exit code / core.
                signal(signum, SIG_DFL)
                raise(signum)
            }
        }
    }

    // write() uses only async-signal-safe C calls so it works from a signal handler.
    private static func write(_ message: String) {
        let timestamp = Date().description
        let full = "[\(timestamp)]\n\(message)\n\n---\n\n"
        guard !logPath.isEmpty else { return }

        // Append to the file (creates it if absent).
        if let data = full.data(using: .utf8) {
            if FileManager.default.fileExists(atPath: logPath) {
                if let handle = FileHandle(forWritingAtPath: logPath) {
                    handle.seekToEndOfFile()
                    handle.write(data)
                    handle.closeFile()
                }
            } else {
                try? data.write(to: URL(fileURLWithPath: logPath))
            }
        }
    }

    /// Call this from the UI to show a share sheet for crash_log.txt, or just
    /// return the contents as a String for display.
    static func readLog() -> String? {
        guard !logPath.isEmpty,
              FileManager.default.fileExists(atPath: logPath) else { return nil }
        return try? String(contentsOfFile: logPath, encoding: .utf8)
    }

    static func clearLog() {
        guard !logPath.isEmpty else { return }
        try? FileManager.default.removeItem(atPath: logPath)
    }
}
