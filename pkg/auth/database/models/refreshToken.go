package models

import "time"

type RefreshToken struct {
	Base
	Jti       string
	ExpiresAt time.Time
}

func NewRefreshToken(jti string, expiresAt time.Time) *RefreshToken {
	return &RefreshToken{
		Jti:       jti,
		ExpiresAt: expiresAt,
	}
}
