import Foundation

@MainActor
class ExtractionManager: ObservableObject {
    @Published var isExtracting = false
    @Published var currentFile: String = ""
    @Published var fileCount: Int = 0
    @Published var lastError: String? = nil
    @Published var finished = false
    @Published var outputURL: URL? = nil

    func extract(pkgURL: URL) {
        isExtracting = true
        finished     = false
        lastError    = nil
        currentFile  = ""
        fileCount    = 0
        outputURL    = nil

        // Config.ini is bundled in the app
        guard let configPath = Bundle.main.path(forResource: "config", ofType: "ini") else {
            lastError   = "config.ini not found in app bundle"
            isExtracting = false
            return
        }

        // Output goes to Documents/Extracted/<pkg-name>/
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let outDir = docs.appendingPathComponent("Extracted")
                         .appendingPathComponent(pkgURL.deletingPathExtension().lastPathComponent)

        let pkgPath  = pkgURL.path
        let outPath  = outDir.path
        let cfgPath  = configPath

        // Unretained self pointer for C callback
        let selfPtr = Unmanaged.passRetained(self).toOpaque()

        Task.detached(priority: .userInitiated) {
            let result = pkg_ios_extract(
                pkgPath,
                outPath,
                cfgPath,
                { ctx, rawPath in
                    guard let ctx, let rawPath else { return }
                    let manager = Unmanaged<ExtractionManager>.fromOpaque(ctx).takeUnretainedValue()
                    let name = String(cString: rawPath)
                    Task { @MainActor in
                        manager.currentFile = name
                        manager.fileCount  += 1
                    }
                },
                selfPtr
            )

            // Release the retained self
            Unmanaged<ExtractionManager>.fromOpaque(selfPtr).release()

            let errMsg: String?
            if result == 0 {
                errMsg = nil
            } else {
                errMsg = String(cString: pkg_ios_last_error())
            }

            await MainActor.run {
                self.isExtracting = false
                self.finished     = true
                self.lastError    = errMsg
                if result == 0 {
                    self.outputURL = outDir
                }
            }
        }
    }
}
