package auth

import (
	"context"
	"errors"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	"github.com/reezanvisram/allergeye/pharmacist/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type grpcServer struct {
	getUserById      grpctransport.Handler
	createUser       grpctransport.Handler
	authenticateUser grpctransport.Handler
}

func NewGRPCServer(endpoints Endpoints) pb.AuthServer {
	return &grpcServer{
		getUserById: grpctransport.NewServer(
			endpoints.GetUserById,
			decodeGRPCGetUserByIdRequest,
			encodeGRPCGetUserByIdResponse,
		),
		createUser: grpctransport.NewServer(
			endpoints.CreateUser,
			decodeGRPCCreateUserRequest,
			encodeGRPCCreateUserResponse,
		),
		authenticateUser: grpctransport.NewServer(
			endpoints.AuthenticateUser,
			decodeGRPCAuthenticateUserRequest,
			encodeGRPCAuthenticateUserResponse,
		),
	}
}

func (s *grpcServer) GetUserById(ctx context.Context, req *pb.GetUserByIdRequest) (*pb.GetUserByIdResponse, error) {
	_, rep, err := s.getUserById.ServeGRPC(ctx, req)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, err
	}
	return rep.(*pb.GetUserByIdResponse), nil
}

func (s *grpcServer) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	_, rep, err := s.createUser.ServeGRPC(ctx, req)
	if err != nil {
		if errors.Is(err, ErrCouldNotCreateUser) {
			return nil, status.Error(codes.Unknown, err.Error())
		} else if errors.Is(err, ErrUserWithEmailExists) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, err
	}
	return rep.(*pb.CreateUserResponse), nil
}

func (s *grpcServer) AuthenticateUser(ctx context.Context, req *pb.AuthenticateUserRequest) (*pb.AuthenticateUserResponse, error) {
	_, rep, err := s.authenticateUser.ServeGRPC(ctx, req)
	if err != nil {
		if errors.Is(err, ErrUserDoesNotExist) || errors.Is(err, ErrIncorrectPassword) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		} else if errors.Is(err, ErrCouldNotCreateRefreshToken) {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	return rep.(*pb.AuthenticateUserResponse), nil
}

func decodeGRPCGetUserByIdRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*pb.GetUserByIdRequest)
	return GetUserByIdRequest{UserId: req.UserId}, nil
}

func encodeGRPCGetUserByIdResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	resp := grpcRes.(GetUserByIdResponse)
	return &pb.GetUserByIdResponse{Username: resp.Username}, nil
}

func decodeGRPCCreateUserRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*pb.CreateUserRequest)
	return CreateUserRequest{Email: req.Email, FirstName: req.FirstName, LastName: req.LastName, Password: req.Password}, nil
}

func encodeGRPCCreateUserResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	resp := grpcRes.(CreateUserResponse)
	return &pb.CreateUserResponse{AccessToken: resp.AccessToken, RefreshToken: resp.RefreshToken}, nil
}

func decodeGRPCAuthenticateUserRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*pb.AuthenticateUserRequest)
	return AuthenticateUserRequest{Email: req.Email, Password: req.Password}, nil
}

func encodeGRPCAuthenticateUserResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	resp := grpcRes.(AuthenticateUserResponse)
	return &pb.AuthenticateUserResponse{AccessToken: resp.AccessToken, RefreshToken: resp.RefreshToken}, nil
}
