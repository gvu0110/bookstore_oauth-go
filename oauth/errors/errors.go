package errors

import "net/http"

// RESTError struct is an custom REST error is used for entire microservice
type RESTError struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
	Error      string `json:"error"`
}

// NewBadRequestRESTError creates a new bad request REST error
func NewBadRequestRESTError(message string) *RESTError {
	return &RESTError{
		StatusCode: http.StatusBadRequest,
		Message:    message,
		Error:      "BAD REQUEST",
	}
}

// NewNotFoundRESTError creates a new not found REST error
func NewNotFoundRESTError(message string) *RESTError {
	return &RESTError{
		StatusCode: http.StatusNotFound,
		Message:    message,
		Error:      "NOT FOUND",
	}
}

// NewInternalServerError creates a new internal server REST error
func NewInternalServerRESTError(message string) *RESTError {
	return &RESTError{
		StatusCode: http.StatusInternalServerError,
		Message:    message,
		Error:      "INTERNAL SERVER ERROR",
	}
}
