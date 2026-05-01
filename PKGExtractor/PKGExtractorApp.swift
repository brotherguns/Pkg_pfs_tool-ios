import SwiftUI

@main
struct PKGExtractorApp: App {
    init() {
        CrashLogger.install()
        createDocumentsPlaceholder()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }

    /// Writes a README into Documents on first launch so the folder
    /// appears in Files app → On My iPhone → PKGExtractor immediately.
    private func createDocumentsPlaceholder() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let readme = docs.appendingPathComponent("README.txt")
        guard !FileManager.default.fileExists(atPath: readme.path) else { return }
        let text = """
PKG Extractor
=============
Drop your .pkg files into this folder using the Files app,
then open PKG Extractor and tap the file to extract it.

Output lands in:  PKGExtractor → Extracted → <pkg-name> → Image0

Crash logs (if any) are written to: PKGExtractor → crash_log.txt
"""
        try? text.write(to: readme, atomically: true, encoding: .utf8)
    }
}
