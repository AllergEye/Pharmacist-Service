// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/auth/service.go

// Package mock_auth is a generated GoMock package.
package mock_auth

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// AuthService is a mock of AuthService interface.
type AuthService struct {
	ctrl     *gomock.Controller
	recorder *AuthServiceMockRecorder
}

// AuthServiceMockRecorder is the mock recorder for AuthService.
type AuthServiceMockRecorder struct {
	mock *AuthService
}

// NewAuthService creates a new mock instance.
func NewAuthService(ctrl *gomock.Controller) *AuthService {
	mock := &AuthService{ctrl: ctrl}
	mock.recorder = &AuthServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *AuthService) EXPECT() *AuthServiceMockRecorder {
	return m.recorder
}

// AuthenticateUser mocks base method.
func (m *AuthService) AuthenticateUser(ctx context.Context, email, password string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthenticateUser", ctx, email, password)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateUser indicates an expected call of AuthenticateUser.
func (mr *AuthServiceMockRecorder) AuthenticateUser(ctx, email, password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateUser", reflect.TypeOf((*AuthService)(nil).AuthenticateUser), ctx, email, password)
}

// CreateUser mocks base method.
func (m *AuthService) CreateUser(ctx context.Context, email, firstName, lastName, password string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUser", ctx, email, firstName, lastName, password)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser.
func (mr *AuthServiceMockRecorder) CreateUser(ctx, email, firstName, lastName, password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*AuthService)(nil).CreateUser), ctx, email, firstName, lastName, password)
}

// GetUserById mocks base method.
func (m *AuthService) GetUserById(ctx context.Context, userId string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserById", ctx, userId)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserById indicates an expected call of GetUserById.
func (mr *AuthServiceMockRecorder) GetUserById(ctx, userId interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserById", reflect.TypeOf((*AuthService)(nil).GetUserById), ctx, userId)
}