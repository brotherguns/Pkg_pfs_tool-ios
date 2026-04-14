//
//  SELFConverter.swift
//
//  Converts a PS4 SELF (Signed ELF) file — such as eboot.bin — into a raw ELF.
//  Ported from ps4_unfself.py by SocraticBliss.
//
//  The SELF wrapper is stripped and ELF segments are reassembled at their
//  correct file offsets, producing a valid ELF binary readable by analysis tools.
//

import Foundation

enum SELFConversionError: LocalizedError {
    case invalidMagic
    case readFailed(String)
    case writeFailed(String)
    case truncated(String)

    var errorDescription: String? {
        switch self {
        case .invalidMagic:          return "Not a valid SELF file (bad magic bytes)"
        case .readFailed(let s):     return "Read failed: \(s)"
        case .writeFailed(let s):    return "Write failed: \(s)"
        case .truncated(let s):      return "File truncated at: \(s)"
        }
    }
}

// MARK: – Low-level read helpers

private func readLE16(_ data: Data, at offset: Int) -> UInt16 {
    UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
}

private func readLE32(_ data: Data, at offset: Int) -> UInt32 {
    UInt32(data[offset])       | (UInt32(data[offset + 1]) << 8) |
    (UInt32(data[offset + 2]) << 16) | (UInt32(data[offset + 3]) << 24)
}

private func readLE64(_ data: Data, at offset: Int) -> UInt64 {
    UInt64(data[offset])       | (UInt64(data[offset + 1]) << 8)  |
    (UInt64(data[offset + 2]) << 16) | (UInt64(data[offset + 3]) << 24) |
    (UInt64(data[offset + 4]) << 32) | (UInt64(data[offset + 5]) << 40) |
    (UInt64(data[offset + 6]) << 48) | (UInt64(data[offset + 7]) << 56)
}

// MARK: – Main converter

struct SELFConverter {

    /// SELF magic: 4F 15 3D 1D
    private static let SELF_MAGIC: [UInt8] = [0x4F, 0x15, 0x3D, 0x1D]

    // -------------------------------------------------------------------------
    // convert(selfURL:elfURL:)
    //
    //  selfURL  – path to the source .bin / SELF file (e.g. eboot.bin)
    //  elfURL   – path to write the resulting .elf  (e.g. eboot.elf)
    // -------------------------------------------------------------------------
    static func convert(selfURL: URL, elfURL: URL) throws {

        // Load the entire SELF into memory (typical eboot is 2–30 MB, fine on iOS)
        let selfData: Data
        do {
            selfData = try Data(contentsOf: selfURL)
        } catch {
            throw SELFConversionError.readFailed(error.localizedDescription)
        }

        var cursor = 0

        // ── 1. SELF header  (struct '<4s4B') ─────────────────────────────────
        //    MAGIC(4), VERSION(1), MODE(1), ENDIAN(1), ATTRIBUTES(1)
        guard selfData.count >= 8 else {
            throw SELFConversionError.truncated("SELF header")
        }
        let magic = [UInt8](selfData[0..<4])
        guard magic == SELF_MAGIC else {
            throw SELFConversionError.invalidMagic
        }
        cursor = 8   // skip MAGIC + VERSION + MODE + ENDIAN + ATTRIBUTES

        // ── 2. SELF extended header  ('<2B2x2HQ2H4x') = 24 bytes ─────────────
        //    CONTENT_TYPE(1), KEY_TYPE(1), PAD(2),
        //    HEADER_SIZE(2), META_SIZE(2), FILE_SIZE(8),
        //    ENTRY_COUNT(2), FLAG(2), PAD(4)
        guard selfData.count >= cursor + 24 else {
            throw SELFConversionError.truncated("SELF extended header")
        }
        let extHeader = selfData[cursor ..< cursor + 24]
        let entryCount = Int(readLE16(extHeader, at: 16))
        cursor += 24

        // ── 3. SELF entries  ('<4Q' × entryCount) = 32 bytes each ─────────────
        //    PROPS(8), FILE_OFFSET(8), FILE_SIZE(8), MEMORY_SIZE(8)
        var segments: [Data] = []
        var lastSegEnd: UInt64 = 0

        for _ in 0 ..< entryCount {
            guard selfData.count >= cursor + 32 else {
                throw SELFConversionError.truncated("SELF entry table")
            }
            let entry = selfData[cursor ..< cursor + 32]
            let fileOffset = readLE64(entry, at: 8)
            let fileSize   = readLE64(entry, at: 16)
            cursor += 32

            // Read the raw segment bytes stored inside the SELF
            let segStart = Int(fileOffset)
            let segEnd   = segStart + Int(fileSize)
            guard selfData.count >= segEnd else {
                throw SELFConversionError.truncated("segment data at 0x\(String(fileOffset, radix: 16))")
            }
            segments.append(selfData[segStart ..< segEnd])
            lastSegEnd = fileOffset + fileSize
        }

        // After the entry table the SELF contains the embedded ELF header.
        // Save this position — this is where we read the ELF from.
        let elfHeaderStart = cursor

        // ── 4. SCE version data (appended after last segment, to EOF) ─────────
        let sceStart = Int(lastSegEnd)
        if selfData.count > sceStart {
            segments.append(selfData[sceStart...])
        }

        // ── 5. ELF identity  ('<4s5B6xB') = 16 bytes ─────────────────────────
        //    EI_MAG(4), EI_CLASS(1), EI_DATA(1), EI_VERSION(1),
        //    EI_OSABI(1), EI_ABIVERSION(1), PAD(6), EI_NIDENT_SIZE(1)
        cursor = elfHeaderStart
        guard selfData.count >= cursor + 16 else {
            throw SELFConversionError.truncated("ELF identity")
        }
        let elfIdent = selfData[cursor ..< cursor + 16]
        cursor += 16

        // ── 6. ELF extension header  ('<2HI3QI6H') = 48 bytes ────────────────
        //    e_type(2), e_machine(2), e_version(4),
        //    e_entry(8), e_phoff(8), e_shoff(8),
        //    e_flags(4),
        //    e_ehsize(2), e_phentsize(2), e_phnum(2),
        //    e_shentsize(2), e_shnum(2), e_shstrndx(2)
        guard selfData.count >= cursor + 48 else {
            throw SELFConversionError.truncated("ELF extension header")
        }
        let elfExt = selfData[cursor ..< cursor + 48]
        let phNum  = Int(readLE16(elfExt, at: 40))   // e_phnum
        let shNum  = Int(readLE16(elfExt, at: 44))   // e_shnum
        cursor += 48

        // ── 7. Build output ELF in memory ─────────────────────────────────────
        // We use NSMutableData so we can seek (overwrite at arbitrary offsets).
        let output = NSMutableData()

        func appendData(_ d: DataProtocol) {
            output.append(contentsOf: d)
        }

        // Write ELF identity + extension header
        appendData(elfIdent)
        appendData(elfExt)

        // ── 8. Program headers  ('<2I6Q') = 56 bytes each ────────────────────
        //    p_type(4), p_flags(4),
        //    p_offset(8), p_vaddr(8), p_paddr(8),
        //    p_filesz(8), p_memsz(8), p_align(8)
        for _ in 0 ..< phNum {
            guard selfData.count >= cursor + 56 else {
                throw SELFConversionError.truncated("ELF program header")
            }
            let ph = selfData[cursor ..< cursor + 56]
            cursor += 56

            let pOffset = readLE64(ph, at: 8)    // p_offset — where segment lives in ELF
            let pFileSz = readLE64(ph, at: 32)   // p_filesz — size in file

            // Write the program header struct
            appendData(ph)

            // Find a matching segment by size and write it at the correct offset
            if pFileSz > 0, let idx = segments.firstIndex(where: { UInt64($0.count) == pFileSz }) {
                let segData   = segments.remove(at: idx)
                let writeAt   = Int(pOffset)
                let writeEnd  = writeAt + segData.count

                // Grow the buffer if needed
                if output.length < writeEnd {
                    let pad = writeEnd - output.length
                    output.append(Data(repeating: 0, count: pad))
                }
                output.replaceBytes(in: NSRange(location: writeAt, length: segData.count),
                                    withBytes: (segData as NSData).bytes)
            }
        }

        // Section headers are read-only in the Python original (they are not
        // written to the output). We skip them here too.
        _ = shNum  // suppress unused-variable warning

        // ── 9. Write ELF to disk ──────────────────────────────────────────────
        do {
            try (output as Data).write(to: elfURL, options: .atomic)
        } catch {
            throw SELFConversionError.writeFailed(error.localizedDescription)
        }
    }

    // -------------------------------------------------------------------------
    // isSELF(url:) – quick magic check, no throws
    // -------------------------------------------------------------------------
    static func isSELF(url: URL) -> Bool {
        guard let fh = FileHandle(forReadingAtPath: url.path) else { return false }
        defer { fh.closeFile() }
        let bytes = [UInt8](fh.readData(ofLength: 4))
        return bytes == SELF_MAGIC
    }
}
