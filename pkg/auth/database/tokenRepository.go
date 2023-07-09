package database

import (
	"time"

	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database/models"
	"gorm.io/gorm"
)

type TokenRepository interface {
	InsertRefreshToken(jti string, expiresAt time.Time) (*models.RefreshToken, error)
	DeleteRefreshTokenByJTI(jti string) error
}

type TokenRepositoryImplementation struct {
	DB *gorm.DB
}

func NewTokenRepository(db *gorm.DB) TokenRepository {
	return TokenRepositoryImplementation{
		DB: db,
	}
}

func (r TokenRepositoryImplementation) InsertRefreshToken(jti string, expiresAt time.Time) (*models.RefreshToken, error) {
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

func (r TokenRepositoryImplementation) DeleteRefreshTokenByJTI(jti string) error {
	refreshToken := models.RefreshToken{
		Jti: jti,
	}

	result := r.DB.Where("jti = ?", jti).Delete(&refreshToken)

	return result.Error
}
