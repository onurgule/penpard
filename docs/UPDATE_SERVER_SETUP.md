# PenPard Auto-Update Setup (GitHub Releases)

PenPard uses `electron-updater` with GitHub Releases for automatic updates.

## How It Works

The auto-updater is configured with the `generic` provider pointing to:

```
https://github.com/penpard/penpard/releases/latest/download
```

When a new version is released on GitHub, users will be notified and can download the update directly from the release assets.

## Required Release Assets

Each GitHub release should include these files:

### Windows
- `PenPard-Setup-{version}.exe` — NSIS installer
- `latest.yml` — Update metadata

### macOS
- `PenPard-{version}-arm64.dmg` — Apple Silicon
- `PenPard-{version}-x64.dmg` — Intel
- `latest-mac.yml` — Update metadata

### Linux
- `PenPard-{version}.AppImage` — AppImage
- `PenPard-{version}_amd64.deb` — Debian package
- `latest-linux.yml` — Update metadata

## Creating a Release

### 1. Build the installers

```bash
# All platforms
npm run pack:all

# Or individually
npm run pack:win
npm run pack:mac
npm run pack:linux
```

### 2. Calculate hashes

```bash
node scripts/calculate-hashes.js
```

### 3. Create GitHub Release

```bash
# Create a tag
git tag v1.0.2
git push origin v1.0.2

# Create release with assets using GitHub CLI
gh release create v1.0.2 \
  dist/PenPard-Setup-1.0.2.exe \
  dist/PenPard-1.0.2-arm64.dmg \
  dist/PenPard-1.0.2-x64.dmg \
  dist/PenPard-1.0.2.AppImage \
  dist/latest.yml \
  dist/latest-mac.yml \
  dist/latest-linux.yml \
  --title "PenPard v1.0.2" \
  --notes "Release notes here"
```

## YAML Metadata Format

### `latest.yml` (Windows)

```yaml
version: 1.0.2
files:
  - url: PenPard-Setup-1.0.2.exe
    sha512: BASE64_ENCODED_SHA512_HASH
    size: 85000000
path: PenPard-Setup-1.0.2.exe
sha512: BASE64_ENCODED_SHA512_HASH
releaseDate: '2026-02-10T10:30:00.000Z'
```

### `latest-mac.yml` (macOS)

```yaml
version: 1.0.2
files:
  - url: PenPard-1.0.2-arm64.dmg
    sha512: BASE64_ENCODED_SHA512_HASH
    size: 95000000
  - url: PenPard-1.0.2-x64.dmg
    sha512: BASE64_ENCODED_SHA512_HASH
    size: 98000000
path: PenPard-1.0.2-arm64.dmg
sha512: BASE64_ENCODED_SHA512_HASH
releaseDate: '2026-02-10T10:30:00.000Z'
```

### `latest-linux.yml` (Linux)

```yaml
version: 1.0.2
files:
  - url: PenPard-1.0.2.AppImage
    sha512: BASE64_ENCODED_SHA512_HASH
    size: 90000000
path: PenPard-1.0.2.AppImage
sha512: BASE64_ENCODED_SHA512_HASH
releaseDate: '2026-02-10T10:30:00.000Z'
```

## SHA512 Hash Calculation

### PowerShell (Windows)
```powershell
$hash = Get-FileHash -Path "PenPard-Setup-1.0.2.exe" -Algorithm SHA512
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($hash.Hash))
```

### Bash (macOS/Linux)
```bash
shasum -a 512 PenPard-1.0.2-arm64.dmg | awk '{print $1}' | xxd -r -p | base64
```

### Node.js
```bash
node scripts/calculate-hashes.js
```

## Notes

1. **HTTPS**: GitHub Releases uses HTTPS by default
2. **electron-updater** automatically checks for the latest release
3. **Code signing** is recommended for macOS but not required for unsigned builds
4. The `electron-builder` automatically generates the `latest*.yml` files in the `dist/` folder during build

## Local Testing

```bash
# Build and serve locally
cd dist
python -m http.server 8080

# Temporarily change UPDATE_SERVER_URL in electron/updater.ts:
# const UPDATE_SERVER_URL = 'http://localhost:8080';
```
