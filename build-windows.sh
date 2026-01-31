#!/bin/bash
# Build script for Windows with websocket fix

echo "Vendoring dependencies..."
go mod vendor

echo "Applying Windows websocket fix..."
WEBSOCKET_FILE="vendor/maunium.net/go/mautrix/appservice/websocket.go"

# Remove the filepath import
sed -i '/"path\/filepath"/d' "$WEBSOCKET_FILE"

# Replace the filepath.Join line with the fixed code
sed -i '/parsed.Path = filepath.Join/c\	// Windows fix: Don'"'"'t use filepath.Join for URL paths as it uses backslashes on Windows\n\t// Use simple string concatenation to ensure forward slashes\n\tif !strings.HasSuffix(parsed.Path, "/") {\n\t\tparsed.Path += "/"\n\t}\n\tparsed.Path += "_matrix/client/unstable/fi.mau.as_sync"' "$WEBSOCKET_FILE"

echo "Building matrix-line for Windows..."
CC=x86_64-w64-mingw32-gcc go build -mod=vendor -o matrix-line.exe ./cmd/matrix-line

if [ $? -eq 0 ]; then
    echo ""
    echo "Build successful: matrix-line.exe"
    echo ""
    echo "To run the bridge:"
    echo "  cd data"
    echo "  ../matrix-line.exe"
else
    echo "Build failed"
    exit 1
fi
