package middleware

import (
	"github.com/justinas/alice"
	"github.com/pianisimo/csrf/db"
	"github.com/pianisimo/csrf/server/middleware/myJwt"
	"github.com/pianisimo/csrf/server/templates"
	"log"
	"net/http"
	"strings"
	"time"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			recover()
		}()
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{
			Csrf:          csrfSecret,
			SecretMessage: "Hello",
		})
	case "/login":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "login", &templates.LoginPage{
				BAlertUser: false,
				AlertMsg:   "",
			})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			user, uuid, loginErr := db.LogUserIn(strings.Join(r.Form["username"], ""),
				strings.Join(r.Form["password"], ""))
			log.Println(user, uuid, loginErr)

			if loginErr != nil {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, user.Role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", templates.RegisterPage{
				BAlertUser: false,
				AlertMsg:   "Register Get",
			})
		case "POST":
			err := r.ParseForm()
			if err != nil {
				w.WriteHeader(http.StatusNotAcceptable)
				log.Panic(err)
			}

			_, uuid, err := db.FetchUserByUserName(strings.Join(r.Form["username"], ""))
			if err == nil {
				w.WriteHeader(http.StatusUnauthorized)
				log.Panic(err)
			} else {
				role := "user"
				uuid, err = db.StoreUser(strings.Join(r.Form["username"], ""),
					strings.Join(r.Form["password"], ""), role)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError),
						http.StatusInternalServerError)
					log.Panic(err)
				}
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError),
						http.StatusInternalServerError)
					log.Panic(err)
				}

				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", http.StatusFound)
	case "/deleteUser":
		log.Println("deleting the user")
		authCookie, authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie {
			log.Println("unauthorized attempt, no auth cookie")
			nullifyTokenCookies(&w, r)
			http.Redirect(w, r, "/login", 302)
			return
		} else if authErr != nil {
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			log.Panicf("panic: %v", authErr)
		}

		uuid, uuidErr := myJwt.GrabUUID(authCookie.Value)
		if uuidErr != nil {
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			log.Panicf("panic: %v", uuidErr)
		}

		db.DeleteUser(uuid)
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/register", 302)

	default:
		w.WriteHeader(http.StatusOK)
	}
}

func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "/logout", "deleteUser":
			authCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! no auth cookie")
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			} else if authErr != nil {
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				log.Panic(authErr)
			}

			refreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! no refresh cookie")
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			} else if refreshErr != nil {
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				log.Panic(authErr)
			}

			requestCsrfToken := grabCsrfFromReq(r)
			log.Println(requestCsrfToken)

			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CheckAndRefreshTokens(authCookie.Value, refreshCookie.Value, requestCsrfToken)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Unauthorized, JWT's not valid")
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				} else {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					log.Panic(err)
				}
			}
			log.Println("Successfully created jwts")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)
		default:
		}

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		MaxAge:   0,
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		MaxAge:   0,
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)
	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		return
	} else if refreshErr != nil {
		http.Error(*w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		log.Panicf("panic!: %v", refreshErr)
	}
	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfFromForm := r.FormValue("X-CSRF-Token")

	if csrfFromForm != "" {
		return csrfFromForm
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}
