package models

type User struct {
	Base
	FirstName      string
	LastName       string
	Email          string
	Password       string
	RefreshTokenID string
	RefreshToken   RefreshToken
}

func NewUser(firstName string, lastName string, email string, password string, refreshToken RefreshToken) *User {
	return &User{
		FirstName:    firstName,
		LastName:     lastName,
		Email:        email,
		Password:     password,
		RefreshToken: refreshToken,
	}
}
