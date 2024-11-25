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

// CORSMiddleware handles Cross-Origin Resource Sharing (CORS) for HTTP requests.
// It allows configuring allowed origins, methods, and headers to enable client-side applications
// to make requests across different domains.
type CORSMiddleware struct {
	AllowedOrigins   []string // List of allowed origins for CORS
	AllowedMethods   []string // List of allowed methods (e.g., GET, POST) for CORS
	AllowedHeaders   []string // List of allowed headers for CORS
	AllowCredentials bool     // Flag to indicate whether credentials are allowed in CORS requests
}

// NewCORSMiddleware creates and returns a new instance of CORSMiddleware with default settings.
func NewCORSMiddleware() *CORSMiddleware {
	return &CORSMiddleware{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization", "X-Requested-With"},
	}
}

// AllowOrigins allows specifying the origins that are allowed for CORS requests.
func (c *CORSMiddleware) AllowOrigins(origins []string) *CORSMiddleware {
	c.AllowedOrigins = origins
	return c
}

// AllowMethods allows specifying the methods that are allowed for CORS requests.
func (c *CORSMiddleware) AllowMethods(methods []string) *CORSMiddleware {
	c.AllowedMethods = methods
	return c
}

// AllowHeaders allows specifying the headers that are allowed for CORS requests.
func (c *CORSMiddleware) AllowHeaders(headers []string) *CORSMiddleware {
	c.AllowedHeaders = headers
	return c
}

// Handler returns a middleware handler for CORS that processes incoming requests and adds appropriate CORS headers.
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

// isOriginAllowed checks if the origin of the incoming request is allowed based on the configured origins.
func (c *CORSMiddleware) isOriginAllowed(origin string) bool {
	for _, Allowedorigin := range c.AllowedOrigins {
		if Allowedorigin == "*" || Allowedorigin == origin {
			return true
		}
	}
	return false
}
