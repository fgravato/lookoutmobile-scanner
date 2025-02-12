package errors

import "fmt"

// APIError represents an error from the API
type APIError struct {
	StatusCode int
	Message    string
	Details    map[string]interface{}
}

// Error implements the error interface
func (e *APIError) Error() string {
	return fmt.Sprintf("API error: %s (status code: %d)", e.Message, e.StatusCode)
}

// NewAPIError creates a new APIError
func NewAPIError(statusCode int, message string, details map[string]interface{}) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    message,
		Details:    details,
	}
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s (field: %s, value: %v)", e.Message, e.Field, e.Value)
}

// NewValidationError creates a new ValidationError
func NewValidationError(field string, value interface{}, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}
