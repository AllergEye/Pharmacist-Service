package auth

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

type Endpoints struct {
	GetUserById      endpoint.Endpoint
	CreateUser       endpoint.Endpoint
	AuthenticateUser endpoint.Endpoint
}

func MakeEndpoints(svc AuthService) Endpoints {
	var getUserByIdEndpoint endpoint.Endpoint
	{
		getUserByIdEndpoint = makeGetUserByIdEndpoint(svc)
	}

	var createUserEndpoint endpoint.Endpoint
	{
		createUserEndpoint = makeCreateUserEndpoint(svc)
	}

	var authenticateUserEndpoint endpoint.Endpoint
	{
		authenticateUserEndpoint = makeAuthenticateUserEndpoint(svc)
	}

	return Endpoints{
		GetUserById:      getUserByIdEndpoint,
		CreateUser:       createUserEndpoint,
		AuthenticateUser: authenticateUserEndpoint,
	}
}

func makeGetUserByIdEndpoint(s AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(GetUserByIdRequest)
		username, err := s.GetUserById(ctx, req.UserId)
		if err != nil {
			return GetUserByIdResponse{}, err
		}
		return GetUserByIdResponse{Username: username, Err: nil}, nil
	}
}

func makeCreateUserEndpoint(s AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(CreateUserRequest)
		tokenPair, err := s.CreateUser(ctx, req.Email, req.FirstName, req.LastName, req.Password)
		if err != nil {
			return CreateUserResponse{}, err
		}
		return CreateUserResponse{AccessToken: tokenPair.AccessToken, RefreshToken: tokenPair.RefreshToken, Err: nil}, nil
	}
}

func makeAuthenticateUserEndpoint(s AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(AuthenticateUserRequest)
		tokenPair, err := s.AuthenticateUser(ctx, req.Email, req.Password)
		if err != nil {
			return AuthenticateUserResponse{}, err
		}
		return AuthenticateUserResponse{AccessToken: tokenPair.AccessToken, RefreshToken: tokenPair.RefreshToken, Err: nil}, nil
	}
}

type GetUserByIdRequest struct {
	UserId string
}

type GetUserByIdResponse struct {
	Username string `json:"username"`
	Err      error  `json:"error"`
}

type CreateUserRequest struct {
	Email     string
	FirstName string
	LastName  string
	Password  string
}

type CreateUserResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	Err          error  `json:"error"`
}

type AuthenticateUserRequest struct {
	Email    string
	Password string
}

type AuthenticateUserResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	Err          error  `json:"error"`
}
