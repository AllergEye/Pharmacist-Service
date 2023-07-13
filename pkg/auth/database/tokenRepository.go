package database

import (
	"time"

	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database/models"
	"gorm.io/gorm"
)

type TokenRepository interface {
	GetRefreshTokenById(refreshTokenId string) (*models.RefreshToken, error)
	GetRefreshTokenByJti(refreshTokenJti string) (*models.RefreshToken, error)
	InsertRefreshToken(jti string, expiresAt time.Time) (*models.RefreshToken, error)
	DeleteRefreshToken(refreshToken *models.RefreshToken) error
}

type TokenRepositoryImplementation struct {
	DB *gorm.DB
}

func NewTokenRepository(db *gorm.DB) TokenRepository {
	return TokenRepositoryImplementation{
		DB: db,
	}
}

func (r TokenRepositoryImplementation) GetRefreshTokenById(refreshTokenId string) (*models.RefreshToken, error) {
	refreshToken := models.RefreshToken{}

	result := r.DB.First(&refreshToken, "id = ?", refreshTokenId)

	if result.Error != nil {
		return nil, result.Error
	}

	return &refreshToken, nil
}

func (r TokenRepositoryImplementation) GetRefreshTokenByJti(refreshTokenJti string) (*models.RefreshToken, error) {
	refreshToken := models.RefreshToken{}

	result := r.DB.First(&refreshToken, "jti = ?", refreshTokenJti)

	if result.Error != nil {
		return nil, result.Error
	}

	return &refreshToken, nil
}

func (r TokenRepositoryImplementation) InsertRefreshToken(jti string, expiresAt time.Time) (*models.RefreshToken, error) {
	refreshToken := models.NewRefreshToken(jti, expiresAt)

	result := r.DB.Create(refreshToken)

	if result.Error != nil {
		return nil, result.Error
	}

	return refreshToken, nil
}

func (r TokenRepositoryImplementation) DeleteRefreshToken(oldRefreshToken *models.RefreshToken) error {
	result := r.DB.Where("jti = ?", oldRefreshToken.Jti).Delete(oldRefreshToken)

	return result.Error
}
