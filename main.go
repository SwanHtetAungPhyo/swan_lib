package swan_lib

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// GlobalJWTMiddleware handles JWT authentication in HTTP requests. It validates the JWT token in the
// Authorization header of incoming requests and ensures that only requests with valid tokens can access protected routes.
type GlobalJWTMiddleware struct {
	Secret string // The secret key used for signing JWT tokens
}

// NewJWTMiddleware creates a new instance of GlobalJWTMiddleware with the provided secret key.
func NewJWTMiddleware(secretKey string) *GlobalJWTMiddleware {
	return &GlobalJWTMiddleware{
		Secret: secretKey,
	}
}

// Authorize is a middleware function that checks if the incoming request contains a valid JWT token
// in the Authorization header. If the token is missing, invalid, or expired, it responds with a 401 Unauthorized error.
func (j *GlobalJWTMiddleware) Authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization Header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Missing Bearer Token", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return nil, fmt.Errorf("could not extract claims")
			}

			if exp, ok := claims["exp"].(float64); ok {
				if time.Now().Unix() > int64(exp) {
					return nil, fmt.Errorf("token has expired")
				}
			}

			return []byte(j.Secret), nil
		})

		if err != nil {
			http.Error(w, "Invalid or Expired Token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// JWTManager provides methods to generate and manage JWT tokens.
type JWTManager struct {
	SecretKey     string        // Secret key used for signing the JWT tokens
	TokenDuration time.Duration // Duration for which the JWT token is valid
}

// NewJWTManager creates and returns a new instance of JWTManager with the specified secret key and token duration.
func NewJWTManager(secretKey string, duration time.Duration) *JWTManager {
	return &JWTManager{
		SecretKey:     secretKey,
		TokenDuration: duration,
	}
}

// GenerateToken creates a new JWT token for the given userID and custom claims.
// The token will be signed with the secret key and will expire after the specified TokenDuration.
func (j *JWTManager) GenerateToken(userID string, customClaims map[string]any) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(j.TokenDuration).Unix(),
		"iat": time.Now().Unix(),
	}

	// Adding custom claims to the token
	for key, value := range customClaims {
		claims[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.SecretKey))
}
