#!/bin/bash
set -euo pipefail
TASK_PROJECT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
TASK_OUTPUT_DIR="${1:-$TASK_PROJECT_DIR/dist}"
TASK_APP_DIR="$TASK_OUTPUT_DIR/游界桥.app"
mkdir -p "$TASK_APP_DIR/Contents/MacOS" "$TASK_APP_DIR/Contents/Resources" "$TASK_PROJECT_DIR/.build"
xcrun swift -module-cache-path "$TASK_PROJECT_DIR/.build/module-cache" "$TASK_PROJECT_DIR/MakeIcon.swift" "$TASK_PROJECT_DIR/Assets/Logo.png" "$TASK_PROJECT_DIR/.build/AppIcon.iconset"
iconutil -c icns "$TASK_PROJECT_DIR/.build/AppIcon.iconset" -o "$TASK_PROJECT_DIR/AppIcon.icns"
cp "$TASK_PROJECT_DIR/Assets/Logo.png" "$TASK_APP_DIR/Contents/Resources/Logo.png"
TASK_GO_BIN="${TASK_GO_BIN:-$TASK_PROJECT_DIR/../toolchains/go/bin/go}"
if [[ ! -x "$TASK_GO_BIN" ]]; then TASK_GO_BIN="$(command -v go)"; fi
export GOPATH="${GOPATH:-$TASK_PROJECT_DIR/../go-cache}"
export GOCACHE="${GOCACHE:-$TASK_PROJECT_DIR/../go-build-cache}"
(cd "$TASK_PROJECT_DIR/Relay" && "$TASK_GO_BIN" build -mod=vendor -trimpath -ldflags='-s -w' -o "$TASK_APP_DIR/Contents/MacOS/PacketRelay" .)
xcrun swiftc -module-cache-path "$TASK_PROJECT_DIR/.build/module-cache" -swift-version 5 -parse-as-library -O -target arm64-apple-macosx13.0 "$TASK_PROJECT_DIR/Sources/Shared.swift" "$TASK_PROJECT_DIR/Sources/Helper.swift" -o "$TASK_APP_DIR/Contents/MacOS/BridgeHelper"
xcrun swiftc -module-cache-path "$TASK_PROJECT_DIR/.build/module-cache" -swift-version 5 -parse-as-library -O -target arm64-apple-macosx13.0 "$TASK_PROJECT_DIR/Sources/Shared.swift" "$TASK_PROJECT_DIR/Sources/App.swift" -o "$TASK_APP_DIR/Contents/MacOS/PS5VPNBridge"
cat > "$TASK_APP_DIR/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>PS5VPNBridge</string>
<key>CFBundleIdentifier</key><string>local.ps5vpnbridge</string>
<key>CFBundleName</key><string>游界桥</string>
<key>CFBundleDisplayName</key><string>游界桥</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>2.5</string>
<key>CFBundleVersion</key><string>11</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSPrincipalClass</key><string>NSApplication</string>
<key>NSLocalNetworkUsageDescription</key><string>将同一 Wi-Fi 中指定 PS5 的 IPv4 流量通过这台 Mac 转发到全球游戏网络。</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
</dict></plist>
PLIST
if [[ -f "$TASK_PROJECT_DIR/AppIcon.icns" ]]; then cp "$TASK_PROJECT_DIR/AppIcon.icns" "$TASK_APP_DIR/Contents/Resources/AppIcon.icns"; fi
if [[ -d "$TASK_PROJECT_DIR/ThirdParty" ]]; then
  mkdir -p "$TASK_APP_DIR/Contents/Resources/ThirdParty"
  cp -f "$TASK_PROJECT_DIR/ThirdParty/"* "$TASK_APP_DIR/Contents/Resources/ThirdParty/"
fi
codesign --force --sign - "$TASK_APP_DIR/Contents/MacOS/PacketRelay"
codesign --force --sign - "$TASK_APP_DIR/Contents/MacOS/BridgeHelper"
codesign --force --sign - "$TASK_APP_DIR"
printf '%s\n' "$TASK_APP_DIR"
