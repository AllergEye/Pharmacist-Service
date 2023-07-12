package lib

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Helpers interface {
	HashPassword(password string) (string, error)
	CheckPasswordHash(hash string, password string) bool
	GenerateRefreshToken() (*jwt.Token, time.Time, string)
}

type HelpersImplementation struct{}

func NewHelpers() Helpers {
	return HelpersImplementation{}
}

func (h HelpersImplementation) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (h HelpersImplementation) CheckPasswordHash(hash string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err == nil
}

func (h HelpersImplementation) GenerateRefreshToken() (*jwt.Token, time.Time, string) {
	jti := uuid.New()
	expiresAt := time.Now().Add(time.Hour * time.Duration(24*30))
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "pharmacist",
		"exp": expiresAt,
		"jti": jti,
	})

	return refreshToken, expiresAt, jti.String()
}
