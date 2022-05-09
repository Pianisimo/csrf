package models

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/pianisimo/csrf/randomstrings"
	"time"
)

type User struct {
	Username, PasswordHash, Role string
}

type TokenClaims struct {
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

const (
	RefreshedTokenValidTime = time.Hour * 72
	AuthTokenValidTime      = time.Minute * 15
)

func GenerateCSRFSecret() (string, error) {
	return randomstrings.GenerateRandomString(32)
}
