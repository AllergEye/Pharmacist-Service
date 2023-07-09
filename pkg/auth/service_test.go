package auth_test

import (
	"context"
	"errors"
	"os"
	"testing"

	. "github.com/reezanvisram/allergeye/pharmacist/pkg/auth"

	"github.com/go-kit/log"
	"github.com/golang/mock/gomock"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database/models"
	mock_database "github.com/reezanvisram/allergeye/pharmacist/pkg/auth/mocks/database"
	"github.com/stretchr/testify/assert"
)

type mock struct {
	authRepo *mock_database.AuthRepository
	logger   log.Logger
}

func makeMocks(t *testing.T) mock {
	ctrl := gomock.NewController(t)
	authRepo := mock_database.NewAuthRepository(ctrl)
	logger := log.NewJSONLogger(os.Stderr)

	return mock{
		authRepo: authRepo,
		logger:   logger,
	}
}

func makeFakeService(m mock) AuthServiceImplementation {
	return AuthServiceImplementation{
		Logger:         m.logger,
		AuthRepository: m.authRepo,
	}
}

func Test_GetUserById(t *testing.T) {
	tests := map[string]struct {
		mocks       func() mock
		given       string
		expectedErr error
	}{
		"it returns no error when given ID is Reezan": {
			mocks: func() mock {
				m := makeMocks(t)
				return m
			},
			given: "Reezan",
		},
		"it returns a user not found error when given ID is not Reezan": {
			mocks: func() mock {
				m := makeMocks(t)
				return m
			},
			expectedErr: ErrUserNotFound,
			given:       "Not Reezan",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := tt.mocks()
			s := makeFakeService(m)
			ctx := context.Background()

			_, err := s.GetUserById(ctx, tt.given)
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}

func Test_CreateUser(t *testing.T) {
	email := "test@test.com"
	firstName := "Joe"
	lastName := "Smith"
	password := "Password2^"

	user := models.User{
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
	}

	randomErr := errors.New("random error")

	tests := map[string]struct {
		mocks       func() mock
		expectedErr error
	}{
		"it returns success if no user with the given email exists and the user is sucessfully inserted": {
			mocks: func() mock {
				m := makeMocks(t)
				m.authRepo.EXPECT().UserExistsWithEmail(email).Return(false)
				m.authRepo.EXPECT().InsertUser(email, firstName, lastName, password).Return(&user, nil)
				return m
			},
		},
		"it returns an error if a user exists with the given email": {
			mocks: func() mock {
				m := makeMocks(t)
				m.authRepo.EXPECT().UserExistsWithEmail(email).Return(true)
				return m
			},
			expectedErr: ErrUserWithEmailExists,
		},
		"it returns an error if the user could not be inserted": {
			mocks: func() mock {
				m := makeMocks(t)
				m.authRepo.EXPECT().UserExistsWithEmail(email).Return(false)
				m.authRepo.EXPECT().InsertUser(email, firstName, lastName, password).Return(nil, randomErr)
				return m
			},
			expectedErr: ErrCouldNotCreateUser,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := tt.mocks()
			s := makeFakeService(m)
			ctx := context.Background()

			_, err := s.CreateUser(ctx, email, firstName, lastName, password)
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}

func Test_AuthenticateUser(t *testing.T) {
	email := "test@test.com"
	password := "Password2^"

	user := models.User{
		Email:     email,
		FirstName: "Test",
		LastName:  "Test",
		Password:  "hash",
	}

	tests := map[string]struct {
		mocks       func() mock
		expectedErr error
	}{
		"successfully authenticates a user if the given username and password match": {
			mocks: func() mock {
				m := makeMocks(t)
				m.authRepo.EXPECT().GetUserByEmail(email).Return(&user, nil)
				m.authRepo.EXPECT().CheckPasswordHash(password, user.Password).Return(true)
				return m
			},
		},
		"returns an error if a user with the given email does not exist": {
			mocks: func() mock {
				m := makeMocks(t)
				m.authRepo.EXPECT().GetUserByEmail(email).Return(nil, database.ErrUserWithEmailDoesNotExistDatabaseError)
				return m
			},
			expectedErr: ErrUserDoesNotExist,
		},
		"returns an error if the user's password is incorrect": {
			mocks: func() mock {
				m := makeMocks(t)
				m.authRepo.EXPECT().GetUserByEmail(email).Return(&user, nil)
				m.authRepo.EXPECT().CheckPasswordHash(password, user.Password).Return(false)
				return m
			},
			expectedErr: ErrIncorrectPassword,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := tt.mocks()
			s := makeFakeService(m)
			ctx := context.Background()

			_, err := s.AuthenticateUser(ctx, email, password)
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}
