package token

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

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
