package jwt

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"

)

type GlobalJWTMiddleware struct {
	Secret string
}


func NewJWTMiddleware(secrectKey *string ) *GlobalJWTMiddleware{
	return &GlobalJWTMiddleware{
		Secret: *secrectKey,
	}
}

func (j * GlobalJWTMiddleware) Authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == " "{
			http.Error(w, "Missing the Authorization Header",http.StatusUnauthorized)
			return 
		}
		
		parts := strings.Split(authHeader," ")
		if len(parts)  != 2 || parts[1] != "Bearer" {
			http.Error(w, "Missing the Bearer Token", http.StatusBadGateway)
			return 
		}

		tokenString := parts[1]
		_, err := jwt.Parse(tokenString, func (token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
			}
			return []byte(j.Secret), nil
		})

		if err != nil {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}