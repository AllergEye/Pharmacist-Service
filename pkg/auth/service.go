package auth

import (
	"context"
	"errors"
	"time"

	"github.com/go-kit/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database"
)

var (
	ErrUserWithEmailExists        = errors.New("user with that email already exists")
	ErrUserDoesNotExist           = errors.New("user does not exist")
	ErrIncorrectPassword          = errors.New("incorrect password")
	ErrCouldNotCreateUser         = errors.New("could not create user")
	ErrUnknownError               = errors.New("an unknown error occurred")
	ErrUserNotFound               = errors.New("user not found")
	ErrCouldNotCreateRefreshToken = errors.New("could not create refresh token")
)

type AuthService interface {
	GetUserById(ctx context.Context, userId string) (string, error)
	CreateUser(ctx context.Context, email string, firstName string, lastName string, password string) (string, error)
	AuthenticateUser(ctx context.Context, email string, password string) (string, error)
}

type authService struct {
	Logger         log.Logger
	AuthRepository database.Repository
	JwtSecret      string
}

func NewBasicAuthService(logger log.Logger, authRepository database.AuthRepository, jwtSecret string) AuthService {
	return authService{
		Logger:         logger,
		AuthRepository: authRepository,
		JwtSecret:      jwtSecret,
	}
}

func (s authService) GetUserById(ctx context.Context, userId string) (string, error) {
	s.Logger.Log("service.GetUserById: userId", userId)
	if userId == "Reezan" {
		return "Reezan", nil
	}

	return "", ErrUserNotFound
}

func (s authService) CreateUser(ctx context.Context, email string, firstName string, lastName string, password string) (string, error) {
	s.Logger.Log("service.CreateUser: Creating user. email", email, "firstName", firstName, "lastName", lastName)

	if s.AuthRepository.UserExistsWithEmail(email) {
		s.Logger.Log("service.CreateUser: User with email already exists. email", email)
		return "", ErrUserWithEmailExists
	}

	generatedRefreshToken, jti := generateRefreshToken()

	expiresAt, err := generatedRefreshToken.Claims.GetExpirationTime()
	if err != nil {
		return "", err
	}

	refreshToken, err := s.AuthRepository.InsertRefreshToken(jti, expiresAt.Time)
	if err != nil {
		return "", ErrCouldNotCreateRefreshToken
	}

	user, err := s.AuthRepository.InsertUser(email, firstName, lastName, password, refreshToken)
	if err != nil {
		return "", ErrCouldNotCreateUser
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "pharmacist",
		"exp":       time.Now().Add(time.Minute * time.Duration(30)),
		"userId":    user.ID,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
	})

	tokenString, err := accessToken.SignedString([]byte(s.JwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func generateRefreshToken() (*jwt.Token, string) {
	jti := uuid.New()
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "pharmacist",
		"exp": time.Now().Add(time.Hour * time.Duration(24*30)),
		"jti": jti,
	})

	return refreshToken, jti.String()
}

func (s authService) AuthenticateUser(ctx context.Context, email string, password string) (string, error) {
	s.Logger.Log("service.AuthenticateUser: Authenticating user. email", email)

	user, err := s.AuthRepository.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, database.ErrUserWithEmailDoesNotExistDatabaseError) {
			return "", ErrUserDoesNotExist
		}
		return "", err
	}

	if !s.AuthRepository.CheckPasswordHash(password, user.Password) {
		return "", ErrIncorrectPassword
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "pharmacist",
		"exp":       time.Now().Add(time.Hour * time.Duration(24)),
		"userId":    user.ID,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
	})

	tokenString, err := accessToken.SignedString([]byte(s.JwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
