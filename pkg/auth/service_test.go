package auth_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/reezanvisram/allergeye/pharmacist/pkg/auth"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database/models"

	"github.com/go-kit/log"
	"github.com/golang/mock/gomock"
	mock_database "github.com/reezanvisram/allergeye/pharmacist/mocks/database"
	mock_lib "github.com/reezanvisram/allergeye/pharmacist/mocks/lib"
	"github.com/stretchr/testify/assert"
)

type mock struct {
	userRepo  *mock_database.MockUserRepository
	tokenRepo *mock_database.MockTokenRepository
	helpers   *mock_lib.MockHelpers
	logger    log.Logger
}

func makeMocks(t *testing.T) mock {
	ctrl := gomock.NewController(t)
	userRepo := mock_database.NewMockUserRepository(ctrl)
	tokenRepo := mock_database.NewMockTokenRepository(ctrl)
	helpers := mock_lib.NewMockHelpers(ctrl)
	logger := log.NewJSONLogger(os.Stderr)

	return mock{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		helpers:   helpers,
		logger:    logger,
	}
}

func makeFakeService(m mock) AuthServiceImplementation {
	return AuthServiceImplementation{
		Logger:          m.logger,
		UserRepository:  m.userRepo,
		TokenRepository: m.tokenRepo,
		Helpers:         m.helpers,
		JwtSecret:       "test-secret",
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
	password := "password"
	hashedPassword := "randomHash"
	user := models.User{
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Password:  hashedPassword,
	}
	testTime := time.Now()
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "pharmacist_test",
		"exp": testTime,
		"jti": "jti",
	})
	refreshToken := models.RefreshToken{
		Jti:       "jti",
		ExpiresAt: testTime,
	}

	randomErr := errors.New("random error")

	tests := map[string]struct {
		mocks       func() mock
		expectedErr error
	}{
		"it returns success if no user with the given email exists and the user is sucessfully inserted": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().UserExistsWithEmail(email).Return(false)
				m.helpers.EXPECT().GenerateRefreshToken().Return(jwtToken, testTime, "jti")
				m.helpers.EXPECT().HashPassword(password).Return(hashedPassword, nil)
				m.userRepo.EXPECT().InsertUser(email, firstName, lastName, hashedPassword, &refreshToken).Return(&user, nil)
				return m
			},
		},
		"it returns an error if a user exists with the given email": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().UserExistsWithEmail(email).Return(true)
				return m
			},
			expectedErr: ErrUserWithEmailExists,
		},
		"it returns an error if there was an error with hashing the password": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().UserExistsWithEmail(email).Return(false)
				m.helpers.EXPECT().GenerateRefreshToken().Return(jwtToken, testTime, "jti")
				m.helpers.EXPECT().HashPassword(password).Return(hashedPassword, randomErr)
				return m
			},
			expectedErr: randomErr,
		},
		"it returns an error if the user could not be inserted": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().UserExistsWithEmail(email).Return(false)
				m.helpers.EXPECT().GenerateRefreshToken().Return(jwtToken, testTime, "jti")
				m.helpers.EXPECT().HashPassword(password).Return(hashedPassword, nil)
				m.userRepo.EXPECT().InsertUser(email, firstName, lastName, hashedPassword, &refreshToken).Return(nil, randomErr)
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
	password := "password"

	testTime := time.Now()
	oldRefreshToken := models.RefreshToken{
		Jti:       "jti",
		ExpiresAt: testTime,
	}
	jti := "jti"
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "pharmacist_test",
		"exp": testTime,
		"jti": jti,
	})
	newRefreshToken := models.RefreshToken{
		Jti:       jti,
		ExpiresAt: testTime,
	}

	user := models.User{
		Email:          email,
		FirstName:      "Test",
		LastName:       "Test",
		Password:       "randomhash",
		RefreshTokenID: "refreshTokenId",
	}

	randomErr := errors.New("random error")

	tests := map[string]struct {
		mocks       func() mock
		expectedErr error
	}{
		"successfully authenticates a user if the given username and password match": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().GetUserByEmail(email).Return(&user, nil)
				m.helpers.EXPECT().CheckPasswordHash(user.Password, password).Return(true)
				m.tokenRepo.EXPECT().GetRefreshTokenById(user.RefreshTokenID).Return(&oldRefreshToken, nil)
				m.helpers.EXPECT().GenerateRefreshToken().Return(jwtToken, testTime, "jti")
				m.tokenRepo.EXPECT().InsertRefreshToken(jti, testTime).Return(&newRefreshToken, nil)
				m.userRepo.EXPECT().UpdateUserRefreshToken(&user, &newRefreshToken).Return(nil)
				m.tokenRepo.EXPECT().DeleteRefreshToken(&oldRefreshToken).Return(nil)
				return m
			},
		},
		"returns an error if a user with the given email does not exist": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().GetUserByEmail(email).Return(nil, database.ErrUserWithEmailDoesNotExistDatabaseError)
				return m
			},
			expectedErr: ErrUserDoesNotExist,
		},
		"returns an error if the user's password is incorrect": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().GetUserByEmail(email).Return(&user, nil)
				m.helpers.EXPECT().CheckPasswordHash(user.Password, password).Return(false)
				return m
			},
			expectedErr: ErrIncorrectPassword,
		},
		"returns an error if the user's old refresh token could not be retrieved": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().GetUserByEmail(email).Return(&user, nil)
				m.helpers.EXPECT().CheckPasswordHash(user.Password, password).Return(true)
				m.tokenRepo.EXPECT().GetRefreshTokenById(user.RefreshTokenID).Return(nil, randomErr)
				return m
			},
			expectedErr: randomErr,
		},
		"returns an error if the user's new refresh token could not be inserted": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().GetUserByEmail(email).Return(&user, nil)
				m.helpers.EXPECT().CheckPasswordHash(user.Password, password).Return(true)
				m.tokenRepo.EXPECT().GetRefreshTokenById(user.RefreshTokenID).Return(&oldRefreshToken, nil)
				m.helpers.EXPECT().GenerateRefreshToken().Return(jwtToken, testTime, "jti")
				m.tokenRepo.EXPECT().InsertRefreshToken(jti, testTime).Return(nil, randomErr)
				return m
			},
			expectedErr: ErrCouldNotCreateRefreshToken,
		},
		"returns an error if the user's new refresh token could not be linked to their account": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().GetUserByEmail(email).Return(&user, nil)
				m.helpers.EXPECT().CheckPasswordHash(user.Password, password).Return(true)
				m.tokenRepo.EXPECT().GetRefreshTokenById(user.RefreshTokenID).Return(&oldRefreshToken, nil)
				m.helpers.EXPECT().GenerateRefreshToken().Return(jwtToken, testTime, "jti")
				m.tokenRepo.EXPECT().InsertRefreshToken(jti, testTime).Return(&newRefreshToken, nil)
				m.userRepo.EXPECT().UpdateUserRefreshToken(&user, &newRefreshToken).Return(randomErr)
				return m
			},
			expectedErr: ErrCouldNotCreateRefreshToken,
		},
		"returns an error if the user's old refresh token could not deleted": {
			mocks: func() mock {
				m := makeMocks(t)
				m.userRepo.EXPECT().GetUserByEmail(email).Return(&user, nil)
				m.helpers.EXPECT().CheckPasswordHash(user.Password, password).Return(true)
				m.tokenRepo.EXPECT().GetRefreshTokenById(user.RefreshTokenID).Return(&oldRefreshToken, nil)
				m.helpers.EXPECT().GenerateRefreshToken().Return(jwtToken, testTime, "jti")
				m.tokenRepo.EXPECT().InsertRefreshToken(jti, testTime).Return(&newRefreshToken, nil)
				m.userRepo.EXPECT().UpdateUserRefreshToken(&user, &newRefreshToken).Return(nil)
				m.tokenRepo.EXPECT().DeleteRefreshToken(&oldRefreshToken).Return(randomErr)
				return m
			},
			expectedErr: randomErr,
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

func Test_GenerateAccessTokenFromRefreshToken(t *testing.T) {

}
