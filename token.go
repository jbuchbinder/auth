package auth

import (
	"github.com/go-martini/martini"
	"net/http"
)

// Token is the authorization token extracted from the request.
type Token string

// TokenFunc returns a Handler that authenticates via an Authentication: Bearer header using the provided function.
// The function should return true for a valid token.
func TokenFunc(authfn func(string) bool) martini.Handler {
	return func(res http.ResponseWriter, req *http.Request, c martini.Context) {
		auth := req.Header.Get("Authorization")
		if len(auth) < 7 || auth[:7] != "Bearer " || !authfn(auth[7:]) {
			http.Error(res, "Not Authorized", http.StatusUnauthorized)
			return
		}
		c.Map(Token(auth[7:]))
	}
}
