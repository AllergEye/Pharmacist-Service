protogen: ./pb/api.proto
	protoc --go_out=. --go_opt=paths=source_relative ./pb/api.proto
	protoc --go-grpc_out=. --go-grpc_opt=require_unimplemented_servers=false,paths=source_relative ./pb/api.proto

run: ./main.go
	go run main.go

test:
	go test ./...