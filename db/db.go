package db

import (
	"errors"
	"github.com/pianisimo/csrf/db/models"
	"github.com/pianisimo/csrf/randomstrings"
	"golang.org/x/crypto/bcrypt"
)

var (
	users         = map[string]models.User{}
	refreshTokens = map[string]string{}
)

func InitDb() {
	refreshTokens = make(map[string]string)
}

func FetchUserByUserName(username string) (user models.User, uuid string, err error) {
	for k, v := range users {
		if v.Username == username {
			user = v
			uuid = k
			return
		}
	}
	err = errors.New("user not found")
	return
}

func FetchUserByUserId(uuid string) (models.User, error) {
	u := users[uuid]
	blankUser := models.User{}

	if blankUser != u {
		return u, nil
	} else {
		return u, errors.New("user not found")
	}
}

func StoreUser(username, password, role string) (uuid string, err error) {
	uuid, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return
	}

	u := models.User{}

	for u != users[uuid] {
		uuid, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return
		}
	}

	hash, err := generateBcryptHash(password)
	if err != nil {
		return
	}

	users[uuid] = models.User{
		Username:     username,
		PasswordHash: hash,
		Role:         role,
	}

	return
}

func StoreRefreshToken() (jti string, err error) {
	jti, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return
	}

	for refreshTokens[jti] != "" {
		jti, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return
		}
	}

	refreshTokens[jti] = "valid"
	return
}

func DeleteRefreshToken(jti string) {
	delete(refreshTokens, jti)
}

func CheckRefreshToken(jti string) bool {
	return refreshTokens[jti] != ""
}

func DeleteUser(uuid string) {
	delete(users, uuid)
}

func LogUserIn(username, password string) (models.User, string, error) {
	user, uuid, err := FetchUserByUserName(username)
	if err != nil {
		return models.User{}, "", err
	}

	return user, uuid, checkPasswordAgainstHash(user.PasswordHash, password)
}

func generateBcryptHash(s string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	return string(hash[:]), err
}

func checkPasswordAgainstHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
