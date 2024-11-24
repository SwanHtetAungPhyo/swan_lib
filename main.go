package swan_lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type (
	GlobalJWTMiddleware struct {
		Secret string
	}
	GlobalResponse struct {
		Message string `json:"message"`
		Body 	any 	`json:"body"`
	}
	ErrorResponseStruct struct {
		Error   error   `json:"error"`
		Message string `json:"message"`
		Status  int    `json:"status,omitempty"` 
	}
)


func NewJWTMiddleware(secrectKey *string ) *GlobalJWTMiddleware{
	return &GlobalJWTMiddleware{
		Secret: *secrectKey,
	}
}

type JWTManager struct {
	SecretKey     string
	TokenDuration time.Duration
}


func NewJWTManager(secretKey string, duration time.Duration) *JWTManager {
	return &JWTManager{
		SecretKey:     secretKey,
		TokenDuration: duration,
	}
}

func (j *JWTManager) GenerateToken(userID string, customClaims map[string]any) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,                     
		"exp": time.Now().Add(j.TokenDuration).Unix(), 
		"iat": time.Now().Unix(),    
	}
	for key, value := range customClaims {
		claims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.SecretKey))
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

func JSONResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}


func ErrorResponse(w http.ResponseWriter, status int, message string, err  error) {
	new  := func(message string, status int ) *ErrorResponseStruct{
		return &ErrorResponseStruct{
			Error: err,
			Status:  status,
			Message: message,
		}
	}
	JSONResponse(w, status, new)
}


func ParseBody(r http.Request, target any) error {
	if r.Body == nil {
		return errors.New("request body is null")
	}

	err := json.NewDecoder(r.Body).Decode(target) 
	if err != nil {
		return errors.New(err.Error())
	}
	return nil 
}