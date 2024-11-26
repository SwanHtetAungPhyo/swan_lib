package swan_lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/valyala/fasthttp"
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
		Body    any    `json:"body"`
	}
	ErrorResponseStruct struct {
		Error   error  `json:"error"`
		Message string `json:"message"`
		Status  int    `json:"status"`
	}
)

func NewJWTMiddleware(secretKey string) *GlobalJWTMiddleware {
	return &GlobalJWTMiddleware{
		Secret: secretKey,
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

func (j *GlobalJWTMiddleware) FastAuthorize(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {

		authHeader := string(ctx.Request.Header.Peek("Authorization"))
		if authHeader == "" {
			ctx.Error("Missing Authorization Header", fasthttp.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			ctx.Error("Missing Bearer Token", fasthttp.StatusUnauthorized)
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
			ctx.Error("Invalid or Expired Token", fasthttp.StatusUnauthorized)
			return
		}

		if !token.Valid {
			ctx.Error("Invalid Token", fasthttp.StatusUnauthorized)
			return
		}

		next(ctx)
	}
}
func JSONResponse(w http.ResponseWriter, status int, message string, data any) {
	var jsonResponseObj = func(message string, data any) *GlobalResponse {
		return &GlobalResponse{
			Message: message,
			Body:    data,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if data != nil {
		if err := json.NewEncoder(w).Encode(jsonResponseObj); err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
		}
	}
}
package swan_lib

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

func (j *GlobalJWTMiddleware) FiberAuthorize() fiber.Handler {
	return func(c *fiber.Ctx) error {

		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing Authorization Header"})
		}


		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing Bearer Token"})
		}

		tokenString := parts[1]


		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		
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
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or Expired Token"})
		}


		if !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid Token"})
		}

	
		return c.Next()
	}
}

func ErrorResponse(w http.ResponseWriter, status int, message string, err error) {
	response := &ErrorResponseStruct{
		Error:   err,
		Status:  status,
		Message: message,
	}
	JSONResponse(w, status, "", response)
}

func ParseBody(r *http.Request, target any) error {
	if r.Body == nil {
		return errors.New("request body is null")
	}

	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		return fmt.Errorf("error decoding request body: %v", err)
	}
	return nil
}
