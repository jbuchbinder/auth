package auth

import (
	"github.com/go-martini/martini"
	"net/http"
)

// AuthToken is the authorization token extracted from the request.
type AuthToken string

// TokenFunc returns a Handler that authenticates via an X-Token header using the provided function.
// The function should return true for a valid token.
func TokenFunc(authfn func(string) bool) martini.Handler {
	return func(res http.ResponseWriter, req *http.Request, c martini.Context) {
		auth := req.Header.Get("X-Token")
		if len(auth) < 2 || !authfn(auth) {
			http.Error(res, "Not Authorized", http.StatusUnauthorized)
			return
		}
		c.Map(AuthToken(auth))
	}
}
