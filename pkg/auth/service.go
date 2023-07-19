package auth

import (
	"context"
	"errors"
	"time"

	"github.com/go-kit/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database/models"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/lib"
)

var (
	ErrUserWithEmailExists        = errors.New("user with that email already exists")
	ErrUserDoesNotExist           = errors.New("user does not exist")
	ErrIncorrectPassword          = errors.New("incorrect password")
	ErrCouldNotCreateUser         = errors.New("could not create user")
	ErrUnknownError               = errors.New("an unknown error occurred")
	ErrUserNotFound               = errors.New("user not found")
	ErrCouldNotCreateRefreshToken = errors.New("could not create refresh token")
	ErrcouldNotUpdateRefreshToken = errors.New("could not update refresh token")
	ErrUnexpectedSigningMethod    = errors.New("unexpected signing method")
	ErrInvalidToken               = errors.New("invalid token")
)

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type refreshTokenClaims struct {
	jwt.RegisteredClaims
	Jti       string    `json:"jti"`
	ExpiresAt time.Time `json:"exp"`
}

type AuthService interface {
	GetUserById(ctx context.Context, userId string) (string, error)
	CreateUser(ctx context.Context, email string, firstName string, lastName string, password string) (TokenPair, error)
	AuthenticateUser(ctx context.Context, email string, password string) (TokenPair, error)
	GenerateAccessTokenFromRefreshToken(ctx context.Context, refreshTokenString string) (TokenPair, error)
}

type AuthServiceImplementation struct {
	Logger          log.Logger
	UserRepository  database.UserRepository
	TokenRepository database.TokenRepository
	Helpers         lib.Helpers
	JwtSecret       string
}

func NewBasicAuthService(logger log.Logger, userRepository database.UserRepository, tokenRepository database.TokenRepository, helpers lib.Helpers, jwtSecret string) AuthService {
	return AuthServiceImplementation{
		Logger:          logger,
		UserRepository:  userRepository,
		TokenRepository: tokenRepository,
		Helpers:         helpers,
		JwtSecret:       jwtSecret,
	}
}

func (s AuthServiceImplementation) GetUserById(ctx context.Context, userId string) (string, error) {
	s.Logger.Log("service.GetUserById: userId", userId)
	if userId == "Reezan" {
		return "Reezan", nil
	}

	return "", ErrUserNotFound
}

func (s AuthServiceImplementation) CreateUser(ctx context.Context, email string, firstName string, lastName string, password string) (TokenPair, error) {
	s.Logger.Log("service.CreateUser:", "Creating User", "email", email, "firstName", firstName, "lastName", lastName)

	if s.UserRepository.UserExistsWithEmail(email) {
		s.Logger.Log("service.CreateUser", "User with email already exists", "email", email)
		return TokenPair{}, ErrUserWithEmailExists
	}

	s.Logger.Log("service.CreateUser", "Creating refresh token", "email", email)
	generatedRefreshToken, expiresAt, jti := s.Helpers.GenerateRefreshToken()
	refreshToken := models.NewRefreshToken(jti, expiresAt)
	hashedPassword, err := s.Helpers.HashPassword(password)
	if err != nil {
		return TokenPair{}, err
	}
	user, err := s.UserRepository.InsertUser(email, firstName, lastName, hashedPassword, refreshToken)
	if err != nil {
		s.Logger.Log("service.CreateUser", "Could not create user", "email", email)
		return TokenPair{}, ErrCouldNotCreateUser
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":    "pharmacist",
		"exp":    time.Now().Add(time.Hour * time.Duration(1)),
		"userId": user.ID,
	})

	accessTokenString, err := accessToken.SignedString([]byte(s.JwtSecret))
	if err != nil {
		return TokenPair{}, err
	}

	refreshTokenString, err := generatedRefreshToken.SignedString([]byte(s.JwtSecret))
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{AccessToken: accessTokenString, RefreshToken: refreshTokenString}, nil
}

func (s AuthServiceImplementation) AuthenticateUser(ctx context.Context, email string, password string) (TokenPair, error) {
	s.Logger.Log("service.AuthenticateUser", "Authenticating user", "email", email)

	user, err := s.UserRepository.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, database.ErrUserWithEmailDoesNotExistDatabaseError) {
			return TokenPair{}, ErrUserDoesNotExist
		}
		return TokenPair{}, err
	}

	if !s.Helpers.CheckPasswordHash(user.Password, password) {
		return TokenPair{}, ErrIncorrectPassword
	}

	oldRefreshToken, err := s.TokenRepository.GetRefreshTokenById(user.RefreshTokenID)
	if err != nil {
		s.Logger.Log("service.AuthenticateUser", "Could not get refresh token by id", "refreshTokenId", user.RefreshTokenID)
		return TokenPair{}, err
	}

	tokenPair, err := s.generateNewRefreshTokenAndRemoveExistingRefreshToken(user, oldRefreshToken)
	if err != nil {
		s.Logger.Log("service.AuthenticateUser", "Could not get generate new refresh token")
		return TokenPair{}, err
	}

	return tokenPair, nil
}

func (s AuthServiceImplementation) GenerateAccessTokenFromRefreshToken(ctx context.Context, refreshTokenString string) (TokenPair, error) {
	s.Logger.Log("service.GenerateAccessTokenFromRefreshToken", "Generating access token from refresh token")

	token, err := jwt.ParseWithClaims(refreshTokenString, &refreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnexpectedSigningMethod
		}
		return []byte(s.JwtSecret), nil
	})
	if err != nil {
		s.Logger.Log("service.GenerateAccessTokenFromRefreshToken", "Could not decode token")
		return TokenPair{}, err
	}
	if _, ok := token.Claims.(*refreshTokenClaims); !ok || !token.Valid {
		s.Logger.Log("service.GenerateAccessTokenFromRefreshToken", "invalid token")
		return TokenPair{}, ErrInvalidToken
	}

	claims := token.Claims.(*refreshTokenClaims)
	jti := claims.Jti
	oldRefreshToken, err := s.TokenRepository.GetRefreshTokenByJti(jti)
	if err != nil {
		s.Logger.Log("service.GenerateAccessTokenFromRefreshToken", "could not get token by JTI")
		return TokenPair{}, err
	}

	user, err := s.UserRepository.GetUserByRefreshTokenId(oldRefreshToken.ID.String())
	if err != nil {
		s.Logger.Log("service.GenerateAccessTokenFromRefreshToken", "could not retrieve user from refresh token")
		return TokenPair{}, err
	}

	tokenPair, err := s.generateNewRefreshTokenAndRemoveExistingRefreshToken(user, oldRefreshToken)
	if err != nil {
		s.Logger.Log("service.GenerateAccessTokenFromRefreshToken", "could not generate new refresh token")
	}
	return tokenPair, nil
}

func (s AuthServiceImplementation) generateNewRefreshTokenAndRemoveExistingRefreshToken(user *models.User, oldRefreshToken *models.RefreshToken) (TokenPair, error) {
	generatedRefreshToken, expiresAt, jti := s.Helpers.GenerateRefreshToken()
	refreshToken, err := s.TokenRepository.InsertRefreshToken(jti, expiresAt)
	if err != nil {
		s.Logger.Log("service.generateNewRefreshToken", "Could not insert refresh token")
		return TokenPair{}, ErrCouldNotCreateRefreshToken
	}
	err = s.UserRepository.UpdateUserRefreshToken(user, refreshToken)
	if err != nil {
		s.Logger.Log("service.generateNewRefreshToken", "Could not update user's refresh token", "userId", user.ID, "refreshTokenId", refreshToken.ID)
		return TokenPair{}, ErrCouldNotCreateRefreshToken
	}

	err = s.TokenRepository.DeleteRefreshToken(oldRefreshToken)
	if err != nil {
		s.Logger.Log("service.generateNewRefreshToken", "could not delete old refresh token", "userId", user.ID)
		return TokenPair{}, err
	}
	generatedAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":    "pharmacist",
		"exp":    time.Now().Add(time.Hour * time.Duration(1)),
		"userId": user.ID,
	})

	accessTokenString, err := generatedAccessToken.SignedString([]byte(s.JwtSecret))
	if err != nil {
		return TokenPair{}, err
	}

	refreshTokenString, err := generatedRefreshToken.SignedString([]byte(s.JwtSecret))
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{AccessToken: accessTokenString, RefreshToken: refreshTokenString}, nil
}
