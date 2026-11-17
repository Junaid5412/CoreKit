#!/usr/bin/env bash
# Builds every desktop target into dist/. Android is built by Gradle (see android/).
#   ./build.sh            -> dist/CoreKit.exe (+ checks)
set -euo pipefail
cd "$(dirname "$0")"
V=$(cat VERSION)
mkdir -p dist
python3 ui/src/build_assets.py >/dev/null
if python3 -c "import PIL" 2>/dev/null; then python3 desktop/build/gen_syso.py >/dev/null; fi
go vet ./...
go test ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet -unsafeptr=false ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.appVersion=$V" -o dist/CoreKit.exe ./desktop
echo "built dist/CoreKit.exe  (v$V)"
