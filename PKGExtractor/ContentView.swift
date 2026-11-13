//
//  ContentView.swift
//
//  Main UI for PKG Extractor.
//  Adds:
//    • File picker sheet — choose which files to extract from a PKG
//    • eboot.bin → eboot.elf conversion status in the result view
//

import SwiftUI

struct ContentView: View {
    @StateObject private var manager = ExtractionManager()

    @State private var pkgFiles:      [URL]         = []
    @State private var selectedPKG:   URL?           = nil

    // Crash log viewer
    @State private var showCrashLog   = false
    @State private var crashLogText   = ""

    // File picker state
    @State private var showFilePicker  = false
    @State private var pickerPKG:      URL?           = nil
    @State private var selectedFiles:  Set<String>   = []

    // Per-PKG passcode / EKC prompt (shown when default keys fail)
    @State private var keyPromptPKG: URL? = nil

    // Bumped on every refresh so rows re-read their file size / split state
    @State private var refreshCount = 0

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {

                // ── Header ────────────────────────────────────────────
                VStack(spacing: 8) {
                    Image(systemName: "square.stack.3d.down.right.fill")
                        .font(.system(size: 52))
                        .foregroundColor(.blue)
                        .padding(.top, 32)

                    Text("PKG Extractor")
                        .font(.largeTitle.bold())

                    Text("Copy .pkg files into this app's folder in Files,\nthen tap a file below to extract it.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)

                    Text("Split PKG: copy every part (name_0.pkg, name_1.pkg, …) and tap the first one.")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                        .padding(.bottom, 12)
                }

                Divider()

                // ── PKG file list ─────────────────────────────────────
                if pkgFiles.isEmpty {
                    Spacer()
                    VStack(spacing: 12) {
                        Image(systemName: "tray")
                            .font(.system(size: 44))
                            .foregroundColor(.secondary)
                        Text("No .pkg files found")
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Text("Open the Files app → On My iPhone → PKGExtractor\nand paste your .pkg file there.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 32)
                        Button(action: refreshList) {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }
                        .buttonStyle(.bordered)
                    }
                    Spacer()
                } else {
                    List(pkgFiles, id: \.path) { url in
                        PKGRow(url: url, isSelected: selectedPKG == url, manager: manager, refreshToken: refreshCount) {
                            beginFilePicking(url: url)
                        }
                    }
                    .listStyle(.insetGrouped)
                }

                Divider()

                // ── Status area ───────────────────────────────────────
                statusArea
                    .padding()
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: refreshList) {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(manager.isExtracting || manager.isListing)
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Open Files") {
                        if let url = URL(string: "shareddocuments://") {
                            UIApplication.shared.open(url)
                        }
                    }
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    if CrashLogger.readLog() != nil {
                        Button {
                            crashLogText = CrashLogger.readLog() ?? ""
                            showCrashLog = true
                        } label: {
                            Label("Crash Log", systemImage: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                        }
                    }
                }
            }
            // ── File picker sheet ──────────────────────────────────────
            .sheet(isPresented: $showFilePicker) {
                if let pkg = pickerPKG {
                    FilePickerSheet(
                        pkgName:       pkg.lastPathComponent,
                        manager:       manager,
                        selectedFiles: $selectedFiles
                    ) {
                        // Extract tapped
                        showFilePicker = false
                        startExtraction(url: pkg, files: selectedFiles)
                    } onCancel: {
                        if let pkg = pickerPKG {
                            manager.saveSelection(selectedFiles, for: pkg)
                        }
                        showFilePicker = false
                        pickerPKG      = nil
                        selectedPKG    = nil
                    }
                }
            }
            // ── Decryption keys sheet ──────────────────────────────────
            .sheet(item: $keyPromptPKG) { pkg in
                KeysSheet(pkg: pkg, manager: manager) {
                    keyPromptPKG = nil
                    beginFilePicking(url: pkg)
                } onCancel: {
                    keyPromptPKG = nil
                    selectedPKG  = nil
                }
            }
            // Listing failed to decrypt -> close the picker and ask for keys for this PKG
            .onChange(of: manager.listError) { err in
                // A split PKG with missing parts is not a key problem: leave the
                // picker open so it shows which part is missing.
                guard let err = err, !PKGSplit.isIncompleteError(err),
                      let pkg = pickerPKG, showFilePicker else { return }
                showFilePicker = false
                pickerPKG      = nil
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    keyPromptPKG = pkg
                }
            }
            // ── Crash log sheet ────────────────────────────────────────
            .sheet(isPresented: $showCrashLog) {
                NavigationView {
                    ScrollView {
                        Text(crashLogText)
                            .font(.system(.caption2, design: .monospaced))
                            .padding()
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .navigationTitle("Crash Log")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .navigationBarLeading) {
                            Button("Close") { showCrashLog = false }
                        }
                        ToolbarItem(placement: .navigationBarTrailing) {
                            Button(role: .destructive) {
                                CrashLogger.clearLog()
                                showCrashLog = false
                            } label: {
                                Text("Clear")
                            }
                        }
                    }
                }
            }
        }
        .onAppear(perform: refreshList)
    }

    // ── Status / progress area ─────────────────────────────────────────────
    @ViewBuilder
    private var statusArea: some View {
        if manager.isListing {
            VStack(spacing: 6) {
                ProgressView()
                    .scaleEffect(1.3)
                Text("Reading PKG contents…")
                    .font(.headline)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(Color(.systemGray6))
            .cornerRadius(12)

        } else if manager.isExtracting {
            VStack(spacing: 6) {
                ProgressView()
                    .scaleEffect(1.3)
                Text("Extracting…")
                    .font(.headline)
                if !manager.currentFile.isEmpty {
                    Text(manager.currentFile)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(2)
                        .multilineTextAlignment(.center)
                }
                Text("\(manager.fileCount) files extracted")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(Color(.systemGray6))
            .cornerRadius(12)

        } else if manager.finished {
            if let err = manager.lastError {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Extraction failed", systemImage: "xmark.circle.fill")
                        .foregroundColor(.red)
                        .font(.headline)
                    ScrollView {
                        Text(err)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.secondary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 400)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
                .background(Color(.systemGray6))
                .cornerRadius(12)

            } else {
                VStack(spacing: 6) {
                    Label("Done — \(manager.fileCount) files", systemImage: "checkmark.circle.fill")
                        .foregroundColor(.green)
                        .font(.headline)
                    if let out = manager.outputURL {
                        Text(out.lastPathComponent)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    // ELF conversion result
                    if let elfMsg = manager.elfConversionResult {
                        Label(elfMsg,
                              systemImage: elfMsg.contains("✓") ? "checkmark.seal.fill" : "info.circle")
                            .font(.caption)
                            .foregroundColor(elfMsg.contains("✓") ? .blue : .secondary)
                    }
                    Text("Output is in PKGExtractor → Extracted in Files app")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color(.systemGray6))
                .cornerRadius(12)
            }

        } else {
            Text("Files app → On My iPhone → PKGExtractor → paste .pkg here")
                .font(.caption2)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────
    private func refreshList() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: docs,
            includingPropertiesForKeys: [.fileSizeKey, .contentModificationDateKey],
            options: .skipsHiddenFiles
        )) ?? []
        let all   = contents.filter { $0.pathExtension.lowercased() == "pkg" }
        let names = Set(all.map { $0.lastPathComponent })
        // Parts 1..N of a split PKG are shown under part 0, not as separate rows.
        // The name alone is not enough: two unrelated whole PKGs called name_0.pkg and
        // name_1.pkg must both stay visible, so the file has to be part of a real split set.
        pkgFiles = all
            .filter { !(PKGSplit.isContinuationPart($0.lastPathComponent, among: names)
                        && PKGSplit.info(for: $0) != nil) }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        refreshCount += 1
    }

    /// Tap handler: start listing files then show the picker sheet.
    private func beginFilePicking(url: URL) {
        guard !manager.isExtracting && !manager.isListing else { return }
        selectedPKG    = url
        pickerPKG      = url
        selectedFiles  = manager.savedSelection(for: url)
        showFilePicker = true
        manager.listFiles(pkgURL: url)
    }

    private func startExtraction(url: URL, files: Set<String>) {
        manager.saveSelection(files, for: url)
        manager.extract(pkgURL: url, selectedFiles: files.isEmpty ? nil : files)
    }
}

// ── Per-PKG passcode / EKC prompt ───────────────────────────────────────────
extension URL: Identifiable {
    public var id: String { absoluteString }
}

struct KeysSheet: View {
    let pkg: URL
    @ObservedObject var manager: ExtractionManager
    let onRetry:  () -> Void
    let onCancel: () -> Void

    @State private var creds = ExtractionManager.Credentials()

    var body: some View {
        NavigationView {
            Form {
                Section(footer: Text("The default keys could not decrypt \(pkg.lastPathComponent). Enter its passcode or EKC and retry.")) {
                    if let err = manager.listError {
                        Text(err.components(separatedBy: "\n").first ?? err)
                            .font(.caption).foregroundColor(.red)
                    }
                }
                Section(
                    header: Text("Passcode"),
                    footer: Text("32 characters. Leave empty to use the default (32 zeros).")
                ) {
                    TextField("00000000000000000000000000000000", text: $creds.passcode)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                    if !creds.passcode.isEmpty && creds.passcode.count != 32 {
                        Text("\(creds.passcode.count)/32 characters")
                            .font(.caption).foregroundColor(.orange)
                    }
                }
                Section(
                    header: Text("EKC"),
                    footer: Text("64 hex characters: content key seed followed by SELF key seed. Needed for finalized game-data packages.")
                ) {
                    TextField("Content key seed + SELF key seed", text: $creds.ekc)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                    if !creds.ekc.isEmpty && !ekcLooksValid {
                        Text("Expected 64 hex characters")
                            .font(.caption).foregroundColor(.orange)
                    }
                }
            }
            .navigationTitle("Keys Required")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Retry") {
                        manager.setCredentials(creds, for: pkg)
                        onRetry()
                    }
                    .disabled(creds.passcode.isEmpty && creds.ekc.isEmpty)
                }
            }
            .onAppear { creds = manager.credentials(for: pkg) }
        }
    }

    private var ekcLooksValid: Bool {
        var t = creds.ekc.filter { !$0.isWhitespace }
        if t.lowercased().hasPrefix("0x") { t.removeFirst(2) }
        return t.count == 64 && t.allSatisfy { $0.isHexDigit }
    }
}

// ── Per-row component ───────────────────────────────────────────────────────
struct PKGRow: View {
    let url:        URL
    let isSelected: Bool
    let manager:    ExtractionManager
    let refreshToken: Int
    let onTap:      () -> Void

    @State private var fileSize = ""
    @State private var split: PKGSplit.Info? = nil

    private var subtitle: String {
        guard let split = split else { return fileSize }
        let total = ByteCountFormatter.string(fromByteCount: Int64(split.totalSize), countStyle: .file)
        return split.isComplete
            ? "\(split.parts) parts · \(total)"
            : "\(split.parts) part\(split.parts == 1 ? "" : "s") found · incomplete (\(total))"
    }

    private func loadInfo() {
        split = PKGSplit.info(for: url)
        if let attrs = try? url.resourceValues(forKeys: [.fileSizeKey]),
           let bytes = attrs.fileSize {
            fileSize = ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
        }
    }

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 14) {
                Image(systemName: "doc.fill")
                    .font(.title2)
                    .foregroundColor(.blue)

                VStack(alignment: .leading, spacing: 2) {
                    Text(url.lastPathComponent)
                        .font(.body)
                        .foregroundColor(.primary)
                        .lineLimit(1)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundColor(split?.isComplete == false ? .orange : .secondary)
                }

                Spacer()

                if isSelected && (manager.isExtracting || manager.isListing) {
                    ProgressView()
                } else {
                    Image(systemName: "chevron.right")
                        .foregroundColor(.secondary)
                        .font(.caption)
                }
            }
            .padding(.vertical, 4)
        }
        .disabled(manager.isExtracting || manager.isListing)
        .onAppear(perform: loadInfo)
        .onChange(of: refreshToken) { _ in loadInfo() }
    }
}

// ── File Picker Sheet ───────────────────────────────────────────────────────
struct FilePickerSheet: View {
    let pkgName:       String
    @ObservedObject var manager: ExtractionManager
    @Binding var selectedFiles: Set<String>
    let onExtract:     () -> Void
    let onCancel:      () -> Void

    @State private var searchText        = ""
    @State private var displayedFiles:   [(path: String, size: UInt64, isDir: Bool)] = []
    @State private var allSelected       = false
    @State private var selectedTotalSize = UInt64(0)

    // Recompute all derived state in one place, called from onChange
    private func recompute() {
        let base = manager.listedFiles
        let filtered = searchText.isEmpty
            ? base
            : base.filter { $0.path.localizedCaseInsensitiveContains(searchText) }
        displayedFiles   = filtered
        allSelected      = !filtered.isEmpty && filtered.allSatisfy { selectedFiles.contains($0.path) }
        selectedTotalSize = base
            .lazy
            .filter { !$0.isDir && selectedFiles.contains($0.path) }
            .reduce(0) { $0 + $1.size }
    }

    var body: some View {
        NavigationView {
            Group {
                if manager.isListing {
                    // Still scanning PKG
                    VStack(spacing: 16) {
                        ProgressView()
                            .scaleEffect(1.4)
                        Text("Reading PKG contents…")
                            .font(.headline)
                        Text(pkgName)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                } else if let err = manager.listError {
                    // Listing failed
                    VStack(spacing: 12) {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 44))
                            .foregroundColor(.red)
                        Text("Could not read PKG contents")
                            .font(.headline)
                        Text(err)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                } else {
                    // File list
                    List {
                        // Select All / None row
                        HStack {
                            Image(systemName: allSelected ? "checkmark.circle.fill" : "circle")
                                .foregroundColor(allSelected ? .blue : .secondary)
                            Text(allSelected ? "Deselect All" : "Select All")
                                .font(.body)
                            Spacer()
                            Text("\(selectedFiles.count) of \(manager.listedFiles.count)")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            if selectedTotalSize > 0 {
                                Text(ByteCountFormatter.string(fromByteCount: Int64(selectedTotalSize), countStyle: .file))
                                    .font(.caption)
                                    .foregroundColor(.blue)
                            }
                        }
                        .contentShape(Rectangle())
                        .onTapGesture {
                            if allSelected {
                                displayedFiles.forEach { selectedFiles.remove($0.path) }
                            } else {
                                displayedFiles.forEach { selectedFiles.insert($0.path) }
                            }
                        }

                        ForEach(displayedFiles, id: \.path) { entry in
                            FilePickerRow(
                                path: entry.path,
                                size: entry.size,
                                isDir: entry.isDir,
                                isSelected: selectedFiles.contains(entry.path)
                            ) {
                                if selectedFiles.contains(entry.path) {
                                    selectedFiles.remove(entry.path)
                                } else {
                                    selectedFiles.insert(entry.path)
                                }
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                    .searchable(text: $searchText, prompt: "Filter files…")
                }
            }
            .navigationTitle("Choose Files")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel", action: onCancel)
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        let text = manager.listedFiles.map { entry in
                            if entry.isDir {
                                return "\(entry.path)/"
                            } else {
                                let formatted = ByteCountFormatter.string(
                                    fromByteCount: Int64(entry.size), countStyle: .file)
                                return "\(entry.path) (\(formatted))"
                            }
                        }.joined(separator: "\n")
                        UIPasteboard.general.string = text
                    } label: {
                        Image(systemName: "doc.on.clipboard")
                    }
                    .disabled(manager.isListing || manager.listedFiles.isEmpty)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        onExtract()
                    } label: {
                        if selectedFiles.isEmpty {
                            Text("Extract All")
                                .bold()
                        } else {
                            Text("Extract (\(selectedFiles.count)) — \(ByteCountFormatter.string(fromByteCount: Int64(selectedTotalSize), countStyle: .file))")
                                .bold()
                        }
                    }
                    .disabled(manager.isListing)
                }
            }
        }
        .onAppear { recompute() }
        .onChange(of: searchText)    { _ in recompute() }
        .onChange(of: selectedFiles) { _ in recompute() }
        .onChange(of: manager.listedFiles.count) { _ in recompute() }
    }
}

// ── Single row in the file picker ───────────────────────────────────────────
struct FilePickerRow: View {
    let path:       String
    let size:       UInt64
    let isDir:      Bool
    let isSelected: Bool
    let onToggle:   () -> Void

    private var icon: String {
        if isDir { return "folder.fill" }
        let ext = (path as NSString).pathExtension.lowercased()
        switch ext {
        case "bin", "elf", "self": return "cpu"
        case "pkg":                return "shippingbox.fill"
        case "sfo":                return "doc.badge.gearshape"
        case "png", "jpg", "dds":  return "photo"
        case "xml", "json":        return "curlybraces"
        default:                   return "doc"
        }
    }

    private var fileName: String {
        (path as NSString).lastPathComponent
    }

    private var directory: String {
        let dir = (path as NSString).deletingLastPathComponent
        return dir.isEmpty ? "" : dir + "/"
    }

    private var sizeLabel: String {
        guard !isDir else { return "" }
        return ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
    }

    var body: some View {
        Button(action: onToggle) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .foregroundColor(.blue)
                    .frame(width: 24)

                VStack(alignment: .leading, spacing: 1) {
                    Text(fileName)
                        .font(.body)
                        .foregroundColor(.primary)
                        .lineLimit(1)
                    if !directory.isEmpty {
                        Text(directory)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                }

                Spacer()

                if !sizeLabel.isEmpty {
                    Text(sizeLabel)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .monospacedDigit()
                }

                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .foregroundColor(isSelected ? .blue : Color(.systemGray4))
                    .font(.title3)
            }
            .padding(.vertical, 2)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

#Preview {
    ContentView()
}
