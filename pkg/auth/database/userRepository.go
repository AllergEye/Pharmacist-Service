package database

import (
	"errors"

	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database/models"
	"gorm.io/gorm"
)

var (
	ErrUserWithEmailDoesNotExistDatabaseError = errors.New("a user with the given email does not exist")
	ErrCouldNotGenerateHash                   = errors.New("could not generate hash")
)

type UserRepository interface {
	InsertUser(email string, firstName string, lastName string, hashedPassword string, refreshToken *models.RefreshToken) (*models.User, error)
	UserExistsWithEmail(email string) bool
	GetUserByEmail(email string) (*models.User, error)
	UpdateUserRefreshToken(user *models.User, refreshToken *models.RefreshToken) error
	ClearRefreshToken(user *models.User) error
}

type UserRepositoryImplementation struct {
	DB *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return UserRepositoryImplementation{
		DB: db,
	}
}

func (r UserRepositoryImplementation) InsertUser(email string, firstName string, lastName string, hashedPassword string, refreshToken *models.RefreshToken) (*models.User, error) {
	user := models.NewUser(firstName, lastName, email, hashedPassword, *refreshToken)

	result := r.DB.Create(user)

	if result.Error != nil {
		return nil, result.Error
	}

	return user, nil
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
