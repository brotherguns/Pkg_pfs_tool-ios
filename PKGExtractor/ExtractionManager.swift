//
//  ExtractionManager.swift
//
//  Manages PKG file listing, filtered extraction, and post-extraction
//  SELF→ELF conversion (eboot.bin → eboot.elf).
//

import Foundation
import UIKit

@MainActor
class ExtractionManager: ObservableObject {

    // ── Extraction state ──────────────────────────────────────────────
    @Published var isExtracting  = false
    @Published var currentFile   = ""
    @Published var fileCount     = 0
    @Published var lastError: String? = nil
    @Published var finished      = false
    @Published var outputURL: URL? = nil

    // ── Listing state ─────────────────────────────────────────────────
    @Published var isListing     = false
    @Published var listedFiles: [(path: String, size: UInt64, isDir: Bool)] = []
    @Published var listError: String? = nil

    // ── SELF conversion state ─────────────────────────────────────────
    @Published var elfConversionResult: String? = nil

    // ── Decryption credentials (persisted, per PKG file name) ─────────
    struct Credentials: Codable, Equatable {
        var passcode = ""   // 32 characters, empty = default (all zeros)
        var ekc      = ""   // 64 hex characters, empty = none
    }

    private static let credsKey = "pkgCredentials"
    private var credentials: [String: Credentials] = {
        guard let data = UserDefaults.standard.data(forKey: ExtractionManager.credsKey),
              let dict = try? JSONDecoder().decode([String: Credentials].self, from: data)
        else { return [:] }
        return dict
    }()

    func credentials(for pkgURL: URL) -> Credentials {
        credentials[pkgURL.lastPathComponent] ?? Credentials()
    }

    func setCredentials(_ creds: Credentials, for pkgURL: URL) {
        let name = pkgURL.lastPathComponent
        if creds == Credentials() { credentials.removeValue(forKey: name) } else { credentials[name] = creds }
        if let data = try? JSONEncoder().encode(credentials) {
            UserDefaults.standard.set(data, forKey: ExtractionManager.credsKey)
        }
        listCache.removeValue(forKey: pkgURL.path)   // cached listing used the old keys
    }

    nonisolated private static func normalizedEKC(_ raw: String) -> String {
        var t = raw.filter { !$0.isWhitespace }
        if t.lowercased().hasPrefix("0x") { t.removeFirst(2) }
        return t
    }

    /// Pushes the saved passcode / EKC into the C layer.
    /// Returns an error message if either value is malformed.
    nonisolated private static func applyCredentials(passcode: String, ekc: String) -> String? {
        let rc = pkg_ios_set_credentials(passcode, normalizedEKC(ekc))
        return rc == 0 ? nil : String(cString: pkg_ios_last_error())
    }

    // ── Saved selections per PKG path ─────────────────────────────────
    private var savedSelections: [String: Set<String>] = [:]

    func savedSelection(for pkgURL: URL) -> Set<String> {
        savedSelections[pkgURL.path] ?? []
    }

    func saveSelection(_ selection: Set<String>, for pkgURL: URL) {
        savedSelections[pkgURL.path] = selection
    }

    // ── File list cache ───────────────────────────────────────────────
    // Key: pkgPath, Value: (mtime at scan time, sorted entries)
    // Invalidated automatically if the file's mtime changes.
    private struct CacheEntry {
        let mtime:   Date
        let entries: [(path: String, size: UInt64, isDir: Bool)]
    }
    private var listCache: [String: CacheEntry] = [:]

    private func cachedEntries(for pkgURL: URL) -> [(path: String, size: UInt64, isDir: Bool)]? {
        guard let entry = listCache[pkgURL.path],
              let mtime = (try? pkgURL.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate,
              mtime == entry.mtime else { return nil }
        return entry.entries
    }

    private func cacheEntries(_ entries: [(path: String, size: UInt64, isDir: Bool)], for pkgURL: URL) {
        guard let mtime = (try? pkgURL.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate else { return }
        listCache[pkgURL.path] = CacheEntry(mtime: mtime, entries: entries)
    }

    // ─────────────────────────────────────────────────────────────────
    // MARK: – List files in a PKG (no extraction)
    // ─────────────────────────────────────────────────────────────────

    /// Enumerate files inside a PKG without writing anything to disk.
    /// Results are stored in `listedFiles`; `listError` is set on failure.
    func listFiles(pkgURL: URL) {
        guard !isListing && !isExtracting else { return }

        // ── Cache hit — serve instantly, no C decryption needed ───────
        if let cached = cachedEntries(for: pkgURL) {
            listedFiles = cached
            listError   = nil
            return
        }

        isListing   = true
        listError   = nil
        listedFiles = []

        guard let configPath = Bundle.main.path(forResource: "config", ofType: "ini") else {
            listError = "config.ini not found in app bundle"
            isListing = false
            return
        }

        let pkgPath  = pkgURL.path
        let cfgPath  = configPath
        let creds    = credentials(for: pkgURL)
        let pass     = creds.passcode
        let ekcValue = creds.ekc
        let selfPtr  = Unmanaged.passRetained(self).toOpaque()

        Task.detached(priority: .userInitiated) {
            if let credErr = ExtractionManager.applyCredentials(passcode: pass, ekc: ekcValue) {
                Unmanaged<ExtractionManager>.fromOpaque(selfPtr).release()
                await MainActor.run {
                    self.listError = credErr
                    self.isListing = false
                }
                return
            }

            let collector = FileEntryCollector()
            let collectorPtr = Unmanaged.passRetained(collector).toOpaque()

            let result = pkg_ios_list_files_ex(
                pkgPath,
                cfgPath,
                { ctx, rawPath, size, isDir in
                    guard let ctx, let rawPath else { return }
                    let col = Unmanaged<FileEntryCollector>.fromOpaque(ctx).takeUnretainedValue()
                    col.append(path: String(cString: rawPath), size: size, isDir: isDir != 0)
                },
                collectorPtr
            )

            Unmanaged<FileEntryCollector>.fromOpaque(collectorPtr).release()
            Unmanaged<ExtractionManager>.fromOpaque(selfPtr).release()

            // Sort on background thread before hitting main actor
            let sorted = result == 0 ? collector.entries.sorted { $0.path < $1.path } : []
            let errMsg = result == 0 ? nil : String(cString: pkg_ios_last_error())

            await MainActor.run {
                self.listedFiles = sorted
                self.listError   = errMsg
                self.isListing   = false
                if errMsg == nil {
                    self.cacheEntries(sorted, for: pkgURL)
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // MARK: – Extract (all files or a filtered subset)
    // ─────────────────────────────────────────────────────────────────

    /// Extract files from a PKG.
    ///
    /// - Parameters:
    ///   - pkgURL:        The PKG file to extract.
    ///   - selectedFiles: Relative paths to extract.  Pass `nil` or an empty
    ///                    set to extract everything.
    func extract(pkgURL: URL, selectedFiles: Set<String>? = nil) {
        guard !isExtracting else { return }

        // ── Free space check ──────────────────────────────────────────
        if let sel = selectedFiles, !sel.isEmpty {
            let needed = listedFiles
                .filter { !$0.isDir && sel.contains($0.path) }
                .reduce(UInt64(0)) { $0 + $1.size }
            if needed > 0 {
                let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
                if let free = (try? docs.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]))?.volumeAvailableCapacityForImportantUsage {
                    if Int64(needed) > free {
                        let neededStr = ByteCountFormatter.string(fromByteCount: Int64(needed), countStyle: .file)
                        let freeStr   = ByteCountFormatter.string(fromByteCount: free, countStyle: .file)
                        lastError = "Not enough free space — need \(neededStr), only \(freeStr) available."
                        finished  = true
                        return
                    }
                }
            }
        }

        isExtracting        = true
        finished            = false
        lastError           = nil
        currentFile         = ""
        fileCount           = 0
        outputURL           = nil
        elfConversionResult = nil

        guard let configPath = Bundle.main.path(forResource: "config", ofType: "ini") else {
            lastError    = "config.ini not found in app bundle"
            isExtracting = false
            finished     = true
            return
        }

        let docs   = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let outDir = docs
            .appendingPathComponent("Extracted")
            .appendingPathComponent(PKGSplit.outputName(for: pkgURL))

        let pkgPath  = pkgURL.path
        let outPath  = outDir.path
        let cfgPath  = configPath
        let creds    = credentials(for: pkgURL)
        let pass     = creds.passcode
        let ekcValue = creds.ekc
        let selfPtr  = Unmanaged.passRetained(self).toOpaque()

        let filterList: [String]? = selectedFiles.flatMap { $0.isEmpty ? nil : Array($0) }

        // ── Background task — prevents iOS killing us mid-extraction ──
        var bgTask: UIBackgroundTaskIdentifier = .invalid
        bgTask = UIApplication.shared.beginBackgroundTask(withName: "PKGExtraction") {
            // Expiration handler — we can't stop the C extraction cleanly,
            // but we mark it so the UI reflects reality when we resume.
            UIApplication.shared.endBackgroundTask(bgTask)
            bgTask = .invalid
        }

        Task.detached(priority: .userInitiated) {

            if let credErr = ExtractionManager.applyCredentials(passcode: pass, ekc: ekcValue) {
                Unmanaged<ExtractionManager>.fromOpaque(selfPtr).release()
                await MainActor.run {
                    self.isExtracting = false
                    self.finished     = true
                    self.lastError    = credErr
                }
                if bgTask != .invalid {
                    await UIApplication.shared.endBackgroundTask(bgTask)
                }
                return
            }

            let result: Int32

            if let filter = filterList, !filter.isEmpty {
                // Filtered extraction via pkg_ios_extract_filtered.
                //
                // NSString.utf8String returns a pointer backed by an autorelease-pool
                // buffer — NOT the NSString's own storage.  The pool can drain at any
                // Swift statement boundary on the cooperative scheduler, leaving a
                // dangling pointer that crashes strcmp in C.  Even keeping NSString
                // objects alive is therefore not sufficient.
                //
                // Fix: strdup() each path into an independent heap allocation.
                // The defer frees them after pkg_ios_extract_filtered returns.
                let cStringPtrs: [UnsafeMutablePointer<CChar>?] = filter.map { strdup($0) }
                defer { cStringPtrs.forEach { if let p = $0 { free(p) } } }

                let constPtrs: [UnsafePointer<CChar>?] = cStringPtrs.map { ptr in ptr.map { UnsafePointer($0) } }
                result = constPtrs.withUnsafeBufferPointer { buf in
                    pkg_ios_extract_filtered(
                        pkgPath,
                        outPath,
                        cfgPath,
                        buf.baseAddress,
                        Int32(buf.count),
                        { ctx, rawPath in
                            guard let ctx, let rawPath else { return }
                            let mgr  = Unmanaged<ExtractionManager>.fromOpaque(ctx).takeUnretainedValue()
                            let name = String(cString: rawPath)
                            Task { @MainActor in
                                mgr.currentFile  = name
                                mgr.fileCount   += 1
                            }
                        },
                        selfPtr
                    )
                }
            } else {
                // Extract everything
                result = pkg_ios_extract(
                    pkgPath,
                    outPath,
                    cfgPath,
                    { ctx, rawPath in
                        guard let ctx, let rawPath else { return }
                        let mgr  = Unmanaged<ExtractionManager>.fromOpaque(ctx).takeUnretainedValue()
                        let name = String(cString: rawPath)
                        Task { @MainActor in
                            mgr.currentFile  = name
                            mgr.fileCount   += 1
                        }
                    },
                    selfPtr
                )
            }

            Unmanaged<ExtractionManager>.fromOpaque(selfPtr).release()

            let errMsg: String? = result == 0 ? nil : String(cString: pkg_ios_last_error())

            // ── Post-extraction: convert eboot.bin → eboot.elf ────────────
            var elfMsg: String? = nil
            if result == 0 {
                elfMsg = await ExtractionManager.convertEBoot(in: outDir)
            }

            await MainActor.run {
                self.isExtracting        = false
                self.finished            = true
                self.lastError           = errMsg
                self.elfConversionResult = elfMsg
                if result == 0 { self.outputURL = outDir }
            }

            if bgTask != .invalid {
                await UIApplication.shared.endBackgroundTask(bgTask)
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // MARK: – eboot.bin → eboot.elf
    // ─────────────────────────────────────────────────────────────────

    /// Searches `outputDir/Image0` for `eboot.bin`, checks whether it is a
    /// SELF, and if so converts it to `eboot.elf` in the same directory.
    ///
    /// Returns a human-readable status string (for display in the UI), or
    /// `nil` if no eboot.bin was present.
    nonisolated static func convertEBoot(in outputDir: URL) async -> String? {
        let image0   = outputDir.appendingPathComponent("Image0")
        let ebootBin = image0.appendingPathComponent("eboot.bin")
        let ebootElf = image0.appendingPathComponent("eboot.elf")

        guard FileManager.default.fileExists(atPath: ebootBin.path) else {
            return nil   // no eboot.bin — nothing to convert
        }

        guard SELFConverter.isSELF(url: ebootBin) else {
            return "eboot.bin found but is not a SELF — skipping conversion"
        }

        do {
            try SELFConverter.convert(selfURL: ebootBin, elfURL: ebootElf)
            return "eboot.bin → eboot.elf ✓"
        } catch {
            return "eboot.elf conversion failed: \(error.localizedDescription)"
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// MARK: – PKGSplit  (split PKGs: name_0.pkg, name_1.pkg, …)
// ─────────────────────────────────────────────────────────────────────

/// A split PKG is the plain byte-wise pieces of one package.  The C layer opens
/// the whole set from the path of any part, so the rest of the app keeps using a
/// single URL; this only helps the UI group the parts and name the output.
enum PKGSplit {

    struct Info {
        let parts: Int
        let totalSize: UInt64
        let isComplete: Bool
    }

    /// Non-nil when `url` belongs to a split PKG.
    static func info(for url: URL) -> Info? {
        var parts: Int32 = 1
        var total: UInt64 = 0
        var complete: Int32 = 1
        guard pkg_ios_split_info(url.path, &parts, &total, &complete) != 0 else { return nil }
        return Info(parts: Int(parts), totalSize: total, isComplete: complete != 0)
    }

    /// `name_003.pkg` -> (prefix "name", digits "003")
    private static func parse(_ fileName: String) -> (prefix: String, digits: String, ext: String)? {
        let ns = fileName as NSString
        let stem = ns.deletingPathExtension
        guard let r = stem.range(of: "_[0-9]+$", options: .regularExpression) else { return nil }
        let digits = String(stem[stem.index(after: r.lowerBound)...])
        return (String(stem[..<r.lowerBound]), digits, ns.pathExtension)
    }

    /// Name-only check: `name_N.pkg` (N > 0) whose `name_0.pkg` is in `names`.
    /// Callers must also confirm the file belongs to a real split set (`info(for:)`).
    static func isContinuationPart(_ fileName: String, among names: Set<String>) -> Bool {
        guard let p = parse(fileName) else { return false }
        // zero-padded numbering (name_00, name_01, …) keeps its width
        let padded = p.digits.count > 1 && p.digits.hasPrefix("0")
        let zero = padded ? String(repeating: "0", count: p.digits.count) : "0"
        if p.digits == zero { return false }
        return names.contains("\(p.prefix)_\(zero).\(p.ext)")
    }

    /// Name for the output folder: `name_0.pkg` -> `name` (plain PKGs keep their stem).
    static func outputName(for url: URL) -> String {
        let stem = url.deletingPathExtension().lastPathComponent
        guard info(for: url) != nil, let p = parse(url.lastPathComponent) else { return stem }
        return p.prefix
    }

    /// Errors the C layer raises for a split set with missing / truncated parts.
    /// They are not key problems, so the UI must not ask for a passcode.
    static func isIncompleteError(_ message: String) -> Bool {
        message.hasPrefix("Incomplete split PKG")
    }
}

// ─────────────────────────────────────────────────────────────────────
// MARK: – FileEntryCollector  (thread-safe accumulator for C callbacks)
// ─────────────────────────────────────────────────────────────────────

private final class FileEntryCollector: @unchecked Sendable {
    private var _entries: [(path: String, size: UInt64, isDir: Bool)] = []
    private let lock = NSLock()

    func append(path: String, size: UInt64, isDir: Bool) {
        lock.lock(); defer { lock.unlock() }
        _entries.append((path: path, size: size, isDir: isDir))
    }

    var entries: [(path: String, size: UInt64, isDir: Bool)] {
        lock.lock(); defer { lock.unlock() }
        return _entries
    }
}
