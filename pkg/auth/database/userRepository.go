package database

import (
	"errors"

	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrUserWithEmailDoesNotExistDatabaseError = errors.New("a user with the given email does not exist")
	ErrCouldNotGenerateHash                   = errors.New("could not generate hash")
)

type UserRepository interface {
	InsertUser(email string, firstName string, lastName string, password string, refreshToken *models.RefreshToken) (*models.User, error)
	UserExistsWithEmail(email string) bool
	GetUserByEmail(email string) (*models.User, error)
	UpdateUserRefreshToken(user *models.User, refreshToken *models.RefreshToken) error
	ClearRefreshToken(user *models.User) error
	HashPassword(password string) (string, error)
	CheckPasswordHash(password string, hash string) bool
}

type UserRepositoryImplementation struct {
	DB *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return UserRepositoryImplementation{
		DB: db,
	}
}

func (r UserRepositoryImplementation) InsertUser(email string, firstName string, lastName string, password string, refreshToken *models.RefreshToken) (*models.User, error) {
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

func (r UserRepositoryImplementation) UserExistsWithEmail(email string) bool {
	var user = models.User{Email: email}
	result := r.DB.Where("email = ?", email).First(&user)

	return !errors.Is(result.Error, gorm.ErrRecordNotFound)
}

func (r UserRepositoryImplementation) GetUserByEmail(email string) (*models.User, error) {
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

func (r UserRepositoryImplementation) UpdateUserRefreshToken(user *models.User, refreshToken *models.RefreshToken) error {
	result := r.DB.Model(user).Select("refresh_token_id").Updates(map[string]interface{}{"refresh_token_id": refreshToken.ID})

	return result.Error
}

func (r UserRepositoryImplementation) ClearRefreshToken(user *models.User) error {
	result := r.DB.Model(user).Select("refresh_token_id").Updates(map[string]interface{}{"refresh_token_id": nil})

	return result.Error
}

func (r UserRepositoryImplementation) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", ErrCouldNotGenerateHash
	}
	return string(bytes), nil
}

func (r UserRepositoryImplementation) CheckPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err == nil
}
