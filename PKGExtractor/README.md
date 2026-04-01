# PKGExtractor — iOS

Native ARM64 PS4 PKG extractor for iPhone. Built from [flatz/pkg_pfs_tool](https://github.com/flatz/pkg_pfs_tool) wrapped in SwiftUI, compiled via GitHub Actions into an unsigned IPA you can sideload with your paid dev cert.

## Setup (one-time)

```sh
# From iSH or any shell with git
git clone https://github.com/brotherguns/Pkg_pfs_tool-ios
cd Pkg_pfs_tool-ios
git add . && git commit -m "init" && git push
```

Then go to **Actions** tab on GitHub → the workflow runs automatically.

When it finishes → **Artifacts** → download `PKGExtractor-unsigned.ipa`.

## Install the IPA

Use **Sideloadly** or **AltStore** with your paid Apple Developer cert:

```sh
# Or with your own cert via codesign:
codesign -f -s "iPhone Developer: ..." PKGExtractor.app
```

## Usage

1. Drop a `.pkg` file into **Files → On My iPhone → PKGExtractor** (or pick it from anywhere via the file picker).
2. Open the app → **Choose PKG File** → pick your `.pkg`.
3. Wait — progress shows live. Output lands in:
   ```
   Files → On My iPhone → PKGExtractor → Extracted → <pkg-name> → Image0 → ...
   ```

## Notes

- Every PKG you use should have an all-zero passcode (already set in `config.ini`).
- Signature and block-hash checks are skipped — works with decrypted/fpkg dumps.
- Runs fully native arm64, no emulation. Dramatically faster than iSH.
- `config.ini` (with PS4 keys) is bundled inside the app at build time.
