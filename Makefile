.PHONY: proto build run clean

proto:
	@echo "Generating protobuf code..."
	@mkdir -p proto
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/user_service.proto

build: proto
	@echo "Building server..."
	@go build -o grpc-vulnerable-server main.go

run: build
	@echo "Running server..."
	@./grpc-vulnerable-server

clean:
	@rm -f grpc-vulnerable-server
	@rm -rf proto/*.pb.go
	@rm -rf proto/*_grpc.pb.go

install-deps:
	@echo "Installing dependencies..."
	@go mod download
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
