#!/bin/bash
# Setup script for gRPC vulnerable project

set -e

echo "Setting up gRPC vulnerable project..."

# Check if protoc is installed
if ! command -v protoc &> /dev/null; then
    echo "Error: protoc is not installed"
    echo "Install with: brew install protobuf (macOS) or apt-get install protobuf-compiler (Linux)"
    exit 1
fi

# Install Go dependencies
echo "Installing Go dependencies..."
go mod download

# Install Go protobuf plugins
echo "Installing Go protobuf plugins..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate Go protobuf code
echo "Generating Go protobuf code..."
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/user_service.proto

# Check if Python is available for Python client
if command -v python3 &> /dev/null; then
    echo "Generating Python protobuf code..."
    python3 -m pip install --quiet grpcio grpcio-tools 2>/dev/null || true
    python3 -m grpc_tools.protoc -I./proto --python_out=. --grpc_python_out=. proto/user_service.proto 2>/dev/null || echo "Python protobuf generation skipped (install grpcio-tools if needed)"
fi

echo "Setup complete!"
echo ""
echo "To run the server:"
echo "  go run main.go"
echo ""
echo "To test with Go client:"
echo "  go run poc.go"
echo ""
echo "To test with Python client:"
echo "  python3 poc.py"
