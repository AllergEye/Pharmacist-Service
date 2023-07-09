package models

import "time"

type RefreshToken struct {
	Base
	Jti       string
	ExpiresAt time.Time
}
