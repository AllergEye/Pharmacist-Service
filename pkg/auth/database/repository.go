package database

import (
	"errors"
	"time"

	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrUserWithEmailDoesNotExistDatabaseError = errors.New("a user with the given email does not exist")
	ErrCouldNotGenerateHash                   = errors.New("could not generate hash")
)

type AuthRepository struct {
	DB *gorm.DB
}

type Repository interface {
	InsertUser(email string, firstName string, lastName string, password string, refreshToken *models.RefreshToken) (*models.User, error)
	InsertRefreshToken(jti string, expiresAt time.Time) (*models.RefreshToken, error)
	UserExistsWithEmail(email string) bool
	GetUserByEmail(email string) (*models.User, error)
	HashPassword(password string) (string, error)
	CheckPasswordHash(password string, hash string) bool
}

func NewRepository(db *gorm.DB) Repository {
	return AuthRepository{
		DB: db,
	}
}

func (r AuthRepository) InsertUser(email string, firstName string, lastName string, password string, refreshToken *models.RefreshToken) (*models.User, error) {
	hashedPwd, err := r.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := models.User{
		Email:        email,
		FirstName:    firstName,
		LastName:     lastName,
		Password:     hashedPwd,
		RefreshToken: *refreshToken,
	}

	result := r.DB.Create(&user)

	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

func (r AuthRepository) InsertRefreshToken(jti string, expiresAt time.Time) (*models.RefreshToken, error) {
	refreshToken := models.RefreshToken{
		Jti:       jti,
		ExpiresAt: expiresAt,
	}

	result := r.DB.Create(&refreshToken)

	if result.Error != nil {
		return nil, result.Error
	}

	return &refreshToken, nil
}

func (r AuthRepository) UserExistsWithEmail(email string) bool {
	var user = models.User{Email: email}
	result := r.DB.Where("email = ?", email).First(&user)

	return !errors.Is(result.Error, gorm.ErrRecordNotFound)
}

func (r AuthRepository) GetUserByEmail(email string) (*models.User, error) {
	var user = models.User{Email: email}
	result := r.DB.Where("email = ?", email).First(&user)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserWithEmailDoesNotExistDatabaseError
		}
		return nil, result.Error
	}

	return &user, nil
}

func (r AuthRepository) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", ErrCouldNotGenerateHash
	}
	return string(bytes), nil
}

func (r AuthRepository) CheckPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err == nil
}
