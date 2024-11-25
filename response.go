package swan_lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// GlobalResponse is used to standardize the response format returned by HTTP handlers.
// It is serialized to JSON and sent to the client with a message and optional data.
type GlobalResponse struct {
	Message string `json:"message"` // A message describing the response
	Body    any    `json:"body"`    // The data returned in the response, can be any type
}

// ErrorResponseStruct is used to standardize error responses sent to the client.
type ErrorResponseStruct struct {
	Error   error  `json:"error"`   // The error encountered
	Message string `json:"message"` // A human-readable message describing the error
	Status  int    `json:"status"`  // HTTP status code for the error response
}

// JSONResponse writes a standardized JSON response with the provided status, message, and data.
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

// ErrorResponse writes an error response with the provided status, message, and error details.
func ErrorResponse(w http.ResponseWriter, status int, message string, err error) {
	response := &ErrorResponseStruct{
		Error:   err,
		Status:  status,
		Message: message,
	}
	JSONResponse(w, status, "", response)
}

// ParseBody parses the body of the incoming HTTP request and decodes it into the target struct.
// It returns an error if the body is empty or if the decoding fails.
func ParseBody(r *http.Request, target any) error {
	if r.Body == nil {
		return errors.New("request body is null")
	}

	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		return fmt.Errorf("error decoding request body: %v", err)
	}
	return nil
}
