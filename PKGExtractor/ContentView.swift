import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var manager = ExtractionManager()
    @State private var showPicker   = false
    @State private var showShareSheet = false

    var body: some View {
        NavigationView {
            VStack(spacing: 24) {

                // Header icon
                Image(systemName: "square.stack.3d.down.right.fill")
                    .font(.system(size: 64))
                    .foregroundColor(.blue)
                    .padding(.top, 32)

                Text("PKG Extractor")
                    .font(.largeTitle.bold())

                Text("Extract PS4 PKG files on-device (arm64 native)")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)

                Divider()

                // Pick PKG button
                Button(action: { showPicker = true }) {
                    Label("Choose PKG File", systemImage: "folder.badge.plus")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
                .disabled(manager.isExtracting)
                .padding(.horizontal)

                // Progress area
                if manager.isExtracting {
                    VStack(spacing: 8) {
                        ProgressView()
                            .scaleEffect(1.4)
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
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    .padding(.horizontal)
                }

                // Result
                if manager.finished {
                    if let err = manager.lastError {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("Extraction failed", systemImage: "xmark.circle.fill")
                                .foregroundColor(.red)
                                .font(.headline)
                            Text(err)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .padding()
                        .background(Color(.systemGray6))
                        .cornerRadius(12)
                        .padding(.horizontal)
                    } else {
                        VStack(spacing: 8) {
                            Label("Done — \(manager.fileCount) files", systemImage: "checkmark.circle.fill")
                                .foregroundColor(.green)
                                .font(.headline)
                            if let url = manager.outputURL {
                                Text(url.path)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .lineLimit(3)
                                    .multilineTextAlignment(.center)
                                Button("Open in Files") {
                                    // Open the Documents folder in Files.app
                                    if let filesURL = URL(string: "shareddocuments://") {
                                        UIApplication.shared.open(filesURL)
                                    }
                                }
                                .buttonStyle(.bordered)
                            }
                        }
                        .padding()
                        .background(Color(.systemGray6))
                        .cornerRadius(12)
                        .padding(.horizontal)
                    }
                }

                Spacer()

                Text("Output: Files → On My iPhone → PKGExtractor → Extracted")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                    .padding(.bottom)
            }
            .navigationBarHidden(true)
        }
        .fileImporter(
            isPresented: $showPicker,
            allowedContentTypes: [UTType(filenameExtension: "pkg") ?? .data],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                // Access security-scoped resource
                guard url.startAccessingSecurityScopedResource() else { return }
                manager.extract(pkgURL: url)
            case .failure(let err):
                manager.lastError = err.localizedDescription
                manager.finished  = true
            }
        }
    }
}

#Preview {
    ContentView()
}
