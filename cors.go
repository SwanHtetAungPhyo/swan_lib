package swan_lib

import (
	"net/http"
	"strings"
)

const (
	ORIGIN_CONTROL      = "Access-Control-Allow-Origin"
	METHOD_CONTROL      = "Access-Control-Allow-Methods"
	HEADER_CONTROL      = "Access-Control-Allow-Headers"
	CREDENTIALS_CONTROL = "Access-Control-Allow-Credentials"
)

type CORSMiddleware struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
}

func NewCORSMiddleware() *CORSMiddleware {
	return &CORSMiddleware{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization", "X-Requested-With"},
	}
}

func (c *CORSMiddleware) AllowOrigins(origins []string) *CORSMiddleware {
	c.AllowedOrigins = origins
	return c
}

func (c *CORSMiddleware) AllowMethods(methods []string) *CORSMiddleware {
	c.AllowedMethods = methods
	return c
}

func (c *CORSMiddleware) AllowHeaders(headers []string) *CORSMiddleware {
	c.AllowedHeaders = headers
	return c
}

func (c *CORSMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origins := r.Header.Get("Origin")
		if !c.isOriginAllowed(origins) {
			w.WriteHeader(http.StatusForbidden)
		}

		w.Header().Set(ORIGIN_CONTROL, origins)
		w.Header().Set(METHOD_CONTROL, strings.Join(c.AllowedMethods, ","))
		w.Header().Set(HEADER_CONTROL, strings.Join(c.AllowedHeaders, ","))
		if c.AllowCredentials {
			w.Header().Set(CREDENTIALS_CONTROL, "true")
		} else {
			w.Header().Set(CREDENTIALS_CONTROL, "false")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (c *CORSMiddleware) isOriginAllowed(origin string) bool {
	for _, Allowedorigin := range c.AllowedOrigins {
		if Allowedorigin == "*" || Allowedorigin == origin {
			return true
		}
	}
	return false
}
