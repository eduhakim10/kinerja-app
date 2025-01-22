package middleware

import (
    "net/http"
    "github.com/julienschmidt/httprouter"
    "log"
)

// AuthMiddleware memeriksa apakah pengguna sudah login
func AuthMiddleware(next httprouter.Handle) httprouter.Handle {
    return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
        cookie, err := r.Cookie("username")
        if err != nil || cookie == nil {
            log.Println("User  not logged in, redirecting to login")
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        log.Printf("Checking user: %s", cookie.Value)
        next(w, r, ps)
    }
}