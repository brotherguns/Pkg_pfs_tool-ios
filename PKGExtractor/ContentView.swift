import SwiftUI

struct ContentView: View {
    @StateObject private var manager = ExtractionManager()
    @State private var pkgFiles: [URL] = []
    @State private var selectedPKG: URL? = nil

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
                        PKGRow(url: url, isSelected: selectedPKG == url, manager: manager) {
                            startExtraction(url: url)
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
                    .disabled(manager.isExtracting)
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Open Files") {
                        if let url = URL(string: "shareddocuments://") {
                            UIApplication.shared.open(url)
                        }
                    }
                }
            }
        }
        .onAppear(perform: refreshList)
    }

    // ── Status / progress area ─────────────────────────────────────────
    @ViewBuilder
    private var statusArea: some View {
        if manager.isExtracting {
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
                    Text(err)
                        .font(.caption)
                        .foregroundColor(.secondary)
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
        pkgFiles = contents
            .filter { $0.pathExtension.lowercased() == "pkg" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private func startExtraction(url: URL) {
        guard !manager.isExtracting else { return }
        selectedPKG = url
        manager.extract(pkgURL: url)
    }
}

// ── Per-row component ──────────────────────────────────────────────────
struct PKGRow: View {
    let url: URL
    let isSelected: Bool
    let manager: ExtractionManager
    let onTap: () -> Void

    @State private var fileSize: String = ""

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
                    Text(fileSize)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Spacer()

                if isSelected && manager.isExtracting {
                    ProgressView()
                } else {
                    Image(systemName: "chevron.right")
                        .foregroundColor(.secondary)
                        .font(.caption)
                }
            }
            .padding(.vertical, 4)
        }
        .disabled(manager.isExtracting)
        .onAppear {
            if let attrs = try? url.resourceValues(forKeys: [.fileSizeKey]),
               let bytes = attrs.fileSize {
                fileSize = ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
            }
        }
    }
}

#Preview {
    ContentView()
}
