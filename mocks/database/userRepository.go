// Code generated by MockGen. DO NOT EDIT.
// Source: ./pkg/auth/database/userRepository.go

// Package mock_database is a generated GoMock package.
package mock_database

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	models "github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database/models"
)

// MockUserRepository is a mock of UserRepository interface.
type MockUserRepository struct {
	ctrl     *gomock.Controller
	recorder *MockUserRepositoryMockRecorder
}

// MockUserRepositoryMockRecorder is the mock recorder for MockUserRepository.
type MockUserRepositoryMockRecorder struct {
	mock *MockUserRepository
}

// NewMockUserRepository creates a new mock instance.
func NewMockUserRepository(ctrl *gomock.Controller) *MockUserRepository {
	mock := &MockUserRepository{ctrl: ctrl}
	mock.recorder = &MockUserRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserRepository) EXPECT() *MockUserRepositoryMockRecorder {
	return m.recorder
}

// ClearRefreshToken mocks base method.
func (m *MockUserRepository) ClearRefreshToken(user *models.User) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClearRefreshToken", user)
	ret0, _ := ret[0].(error)
	return ret0
}

// ClearRefreshToken indicates an expected call of ClearRefreshToken.
func (mr *MockUserRepositoryMockRecorder) ClearRefreshToken(user interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClearRefreshToken", reflect.TypeOf((*MockUserRepository)(nil).ClearRefreshToken), user)
}

// GetUserByEmail mocks base method.
func (m *MockUserRepository) GetUserByEmail(email string) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByEmail", email)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByEmail indicates an expected call of GetUserByEmail.
func (mr *MockUserRepositoryMockRecorder) GetUserByEmail(email interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByEmail", reflect.TypeOf((*MockUserRepository)(nil).GetUserByEmail), email)
}

// GetUserByRefreshTokenId mocks base method.
func (m *MockUserRepository) GetUserByRefreshTokenId(refreshTokenId string) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByRefreshTokenId", refreshTokenId)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByRefreshTokenId indicates an expected call of GetUserByRefreshTokenId.
func (mr *MockUserRepositoryMockRecorder) GetUserByRefreshTokenId(refreshTokenId interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByRefreshTokenId", reflect.TypeOf((*MockUserRepository)(nil).GetUserByRefreshTokenId), refreshTokenId)
}

// InsertUser mocks base method.
func (m *MockUserRepository) InsertUser(email, firstName, lastName, hashedPassword string, refreshToken *models.RefreshToken) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertUser", email, firstName, lastName, hashedPassword, refreshToken)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertUser indicates an expected call of InsertUser.
func (mr *MockUserRepositoryMockRecorder) InsertUser(email, firstName, lastName, hashedPassword, refreshToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertUser", reflect.TypeOf((*MockUserRepository)(nil).InsertUser), email, firstName, lastName, hashedPassword, refreshToken)
}

// UpdateUserRefreshToken mocks base method.
func (m *MockUserRepository) UpdateUserRefreshToken(user *models.User, refreshToken *models.RefreshToken) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUserRefreshToken", user, refreshToken)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateUserRefreshToken indicates an expected call of UpdateUserRefreshToken.
func (mr *MockUserRepositoryMockRecorder) UpdateUserRefreshToken(user, refreshToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUserRefreshToken", reflect.TypeOf((*MockUserRepository)(nil).UpdateUserRefreshToken), user, refreshToken)
}

// UserExistsWithEmail mocks base method.
func (m *MockUserRepository) UserExistsWithEmail(email string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UserExistsWithEmail", email)
	ret0, _ := ret[0].(bool)
	return ret0
}

// UserExistsWithEmail indicates an expected call of UserExistsWithEmail.
func (mr *MockUserRepositoryMockRecorder) UserExistsWithEmail(email interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserExistsWithEmail", reflect.TypeOf((*MockUserRepository)(nil).UserExistsWithEmail), email)
}
