package myJwt

import (
	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/pianisimo/csrf/db"
	"github.com/pianisimo/csrf/db/models"
	"io/ioutil"
	"log"
	"time"
)

const (
	privateKeyPath = "keys/app.rsa"
	publicKeyPath  = "keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func InitJWT() error {
	signBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}
	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	return nil
}

func CreateNewTokens(uuid, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}

	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}

	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}

	return
}

func CheckAndRefreshTokens(authTokenString, refreshTokenString, csrfToken string) (newAuthTokenString,
	newRefreshTokenString, newCsrfSecret string, err error) {
	if csrfToken == "" {
		log.Println("No CSRF token")
		err = errors.New("unauthorized")
		return
	}

	authToken, err := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return
	}

	authClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	if csrfToken != authClaims.Csrf {
		log.Println("CSRF token doesn't match jwt")
		err = errors.New("unauthorized")
		return
	}

	if authToken.Valid {
		log.Println("Auth token is valid")
		newCsrfSecret = authClaims.Csrf
		newRefreshTokenString, err = updateRefreshTokenExp(refreshTokenString)
		newAuthTokenString = authTokenString
		return
	} else {
		ve, ok := err.(*jwt.ValidationError)
		if !ok {
			log.Println("Auth token is not valid")
			if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
				log.Println("Auth token is expired")
				newAuthTokenString, newCsrfSecret, err = updateAuthTokenString(refreshTokenString, authTokenString)
				if err != nil {
					return
				}

				newRefreshTokenString, err = updateRefreshTokenExp(refreshTokenString)
				if err != nil {
					return
				}

				newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
				if err != nil {
					return
				}
			} else {
				log.Println("error in auth token")
				err = errors.New("error in auth token")
				return
			}
		} else {
			log.Println("error in auth token")
			err = errors.New("error in auth token")
			return
		}
	}
	err = errors.New("unauthorized")
	return
}

func createAuthTokenString(uuid, role, csrfSecret string) (authTokenString string, err error) {
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: authTokenExp,
			Subject:   uuid,
		},
		Role: role,
		Csrf: csrfSecret,
	}

	authJwt := jwt.NewWithClaims(jwt.SigningMethodRS256, authClaims)
	authTokenString, err = authJwt.SignedString(signKey)
	return
}

func createRefreshTokenString(uuid, role, csrfSecret string) (refreshTokenString string, err error) {
	refreshTokenExp := time.Now().Add(models.RefreshedTokenValidTime).Unix()
	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: refreshTokenExp,
			Subject:   uuid,
		},
		Role: role,
		Csrf: csrfSecret,
	}

	db.StoreRefreshToken()

	refreshJwt := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func updateRefreshTokenExp(tokenString string) (newTokenString string, err error) {
	oldToken, err := jwt.ParseWithClaims(tokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return
	}

	oldClaims, ok := oldToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("can't parse old claims")
		return
	}

	tokenExp := time.Now().Add(models.RefreshedTokenValidTime).Unix()

	claims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: tokenExp,
			Id:        oldClaims.StandardClaims.Id,
			Subject:   oldClaims.StandardClaims.Subject,
		},
		Role: oldClaims.Role,
		Csrf: oldClaims.Csrf,
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	newTokenString, err = newToken.SignedString(signKey)
	return
}

func updateAuthTokenString(refreshTokenString string, oldAuthTokenString string) (newAuthTokenString, csrfSecret string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("Error reading jwt claims")
		return
	}

	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id) {

		if refreshToken.Valid {

			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})

			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok {
				err = errors.New("Error reading jwt claims")
				return
			}

			csrfSecret, err = models.GenerateCSRFSecret()
			if err != nil {
				return
			}

			newAuthTokenString, err = createAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)

			return
		} else {
			log.Println("Refresh token has expired!")

			db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

			err = errors.New("Unauthorized")
			return
		}
	} else {
		log.Println("Refresh token has been revoked!")

		err = errors.New("Unauthorized")
		return
	}
}

func RevokeRefreshToken(refreshTokenString string) error {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if err != nil {
		return err
	}

	refreshClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return errors.New("casting claims error")
	}

	db.DeleteRefreshToken(refreshClaims.StandardClaims.Id)
	return nil
}

func updateRefreshTokenCsrf(refreshTokenString, csrfSecret string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if err != nil {
		return
	}

	refreshClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("casting claims error")
		return
	}

	newRefreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: refreshClaims.StandardClaims.ExpiresAt,
			Id:        refreshClaims.StandardClaims.Id,
			Subject:   refreshClaims.StandardClaims.Subject,
		},
		Role: refreshClaims.Role,
		Csrf: csrfSecret,
	}

	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, newRefreshClaims)

	newRefreshTokenString, err = newRefreshToken.SignedString(signKey)
	return
}

func GrabUUID(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return "", errors.New("error fetching claims")
	})

	if err != nil {
		return "", errors.New("error fetching claims")
	}

	claims, ok := token.Claims.(*models.TokenClaims)
	if !ok {
		return "", errors.New("error fetching claims")
	}

	return claims.StandardClaims.Subject, nil
}
