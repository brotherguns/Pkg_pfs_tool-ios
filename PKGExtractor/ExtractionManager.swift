//
//  ExtractionManager.swift
//
//  Manages PKG file listing, filtered extraction, and post-extraction
//  SELF→ELF conversion (eboot.bin → eboot.elf).
//

import Foundation

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
    @Published var listedFiles: [String] = []
    @Published var listError: String? = nil

    // ── SELF conversion state ─────────────────────────────────────────
    @Published var elfConversionResult: String? = nil

    // ─────────────────────────────────────────────────────────────────
    // MARK: – List files in a PKG (no extraction)
    // ─────────────────────────────────────────────────────────────────

    /// Enumerate files inside a PKG without writing anything to disk.
    /// Results are stored in `listedFiles`; `listError` is set on failure.
    func listFiles(pkgURL: URL) {
        guard !isListing && !isExtracting else { return }

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
        let selfPtr  = Unmanaged.passRetained(self).toOpaque()

        Task.detached(priority: .userInitiated) {
            // Accumulate paths in a thread-safe array (C callback fires on background thread)
            let collector = PathCollector()
            let collectorPtr = Unmanaged.passRetained(collector).toOpaque()

            let result = pkg_ios_list_files(
                pkgPath,
                cfgPath,
                { ctx, rawPath in
                    guard let ctx, let rawPath else { return }
                    let col = Unmanaged<PathCollector>.fromOpaque(ctx).takeUnretainedValue()
                    col.append(String(cString: rawPath))
                },
                collectorPtr
            )

            Unmanaged<PathCollector>.fromOpaque(collectorPtr).release()
            Unmanaged<ExtractionManager>.fromOpaque(selfPtr).release()

            let paths   = collector.paths
            let errMsg  = result == 0 ? nil : String(cString: pkg_ios_last_error())

            await MainActor.run {
                self.listedFiles = paths.sorted()
                self.listError   = errMsg
                self.isListing   = false
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
            .appendingPathComponent(pkgURL.deletingPathExtension().lastPathComponent)

        let pkgPath  = pkgURL.path
        let outPath  = outDir.path
        let cfgPath  = configPath
        let selfPtr  = Unmanaged.passRetained(self).toOpaque()

        // Build a C-compatible filter array (lives for the duration of the task)
        let filterList: [String]? = selectedFiles.flatMap { $0.isEmpty ? nil : Array($0) }

        Task.detached(priority: .userInitiated) {

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

                let constPtrs: [UnsafePointer<CChar>?] = cStringPtrs.map { $0.map(UnsafePointer.init) }
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
// MARK: – PathCollector  (thread-safe accumulator for C callbacks)
// ─────────────────────────────────────────────────────────────────────

private final class PathCollector: @unchecked Sendable {
    private var _paths: [String] = []
    private let lock = NSLock()

    func append(_ path: String) {
        lock.lock(); defer { lock.unlock() }
        _paths.append(path)
    }

    var paths: [String] {
        lock.lock(); defer { lock.unlock() }
        return _paths
    }
}
