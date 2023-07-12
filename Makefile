protogen: ./pb/api.proto
	protoc --go_out=. --go_opt=paths=source_relative ./pb/api.proto
	protoc --go-grpc_out=. --go-grpc_opt=require_unimplemented_servers=false,paths=source_relative ./pb/api.proto

generate-mocks:
	mockgen -source=./pkg/auth/database/userRepository.go -destination=./pkg/auth/mocks/database/userRepository.go -mock_names=UserRepository=MockUserRepository
	mockgen -source=./pkg/auth/database/tokenRepository.go -destination=./pkg/auth/mocks/database/tokenRepository.go -mock_names=TokenRepository=MockTokenRepository
	mockgen -source=./pkg/auth/service.go -destination=./pkg/auth/mocks/service.go -mock_names=AuthService=MockAuthService

run: ./main.go
	go run main.go

test:
	go test ./...