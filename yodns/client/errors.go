package client

import (
	"errors"
	"fmt"
)

const (
	// ErrorCodeCancelled indicates that the operation was cancelled before it could finish
	ErrorCodeCancelled = "CANCELLED"

	// ErrorCodeWriteMessage indicates that the message could not be written to the wire.
	ErrorCodeWriteMessage = "WRITE_MESSAGE"

	// ErrorCodeMessageTooLarge indicates that the message was too large to be written
	ErrorCodeMessageTooLarge = "MESSAGE_TOO_LARGE"

	// ErrorCodeGracePeriodBegun indicates that a write operation was attempted on a connection
	// that has entered its grace period before getting closed
	ErrorCodeGracePeriodBegun = "GRACE_PERIOD_BEGUN"

	// ErrorCodeDial indicates that it was not possible to establish a connection to the server.
	ErrorCodeDial = "DIAL_TCP"

	// ErrorCodeRateLimitTimeout indicates that the request timed out because it was rate-limited for too long.
	ErrorCodeRateLimitTimeout = "RATE_LIMIT_TIMEOUT"

	// ErrorCodeImpossibleRateLimit indicates that the rate limiting conditions could not be met.
	ErrorCodeImpossibleRateLimit = "IMPOSSIBLE_RATE_LIMIT_TIMEOUT"

	// ErrorCodePredictedRateLimitTimeout indicates that a request was failed early,
	// because it would not have been possible to send the request before the rate limiting timeout
	ErrorCodePredictedRateLimitTimeout = "RATE_LIMIT_TIMEOUT_PREDICTED"

	// ErrorCodeReceiveTimeout indicates that no response was received in due time.
	ErrorCodeReceiveTimeout = "RECEIVE_TIMEOUT"

	// ErrorCodePoolExhausted indicates that the connection pool was not able to provide a connection.
	// This may indicate that not enough ports were available
	ErrorCodePoolExhausted = "POOL_EXHAUSTED"

	// ErrorCodeEphemeralExhausted indicates that all ephemeral TCP connections are currently in use
	ErrorCodeEphemeralExhausted = "EPHEMERAL_EXHAUSTED"

	// ErrorCodeReceiveOnClosedConn indicates that a receive operation was tried on a closed connection.
	// This may indicate an internal problem of the client library
	ErrorCodeReceiveOnClosedConn = "RECEIVE_ON_CLOSED_CONN"

	// ErrorCodeCorruptedMessage indicates that a message could not be read, e.g. because
	// the length in the header did not correspond to the actual message length or because
	// the message body was not conforming to the standard
	ErrorCodeCorruptedMessage = "CORRUPTED_MESSAGE"

	// ErrorCodeRead indicates an unspecified error when reading a message
	ErrorCodeRead = "READ_ERROR"

	// ErrorCodeInvalidAddress indicates that the Value (of the server) is not valid.
	ErrorCodeInvalidAddress = "INVALID_ADDR"
)

var (
	ErrCancelled        = Error{Code: ErrorCodeCancelled}
	ErrWriteMessage     = Error{Code: ErrorCodeWriteMessage}
	ErrMessageTooLarge  = Error{Code: ErrorCodeMessageTooLarge}
	ErrGracePeriodBegun = Error{Code: ErrorCodeGracePeriodBegun}

	ErrRateLimitTimeout           = Error{Code: ErrorCodeRateLimitTimeout}
	ErrPredicatedRateLimitTimeout = Error{Code: ErrorCodePredictedRateLimitTimeout}
	ErrImpossibleRateLimit        = Error{Code: ErrorCodeImpossibleRateLimit}

	ErrReceiveTimeout      = Error{Code: ErrorCodeReceiveTimeout}
	ErrDial                = Error{Code: ErrorCodeDial}
	ErrReceiveOnClosedConn = Error{Code: ErrorCodeReceiveOnClosedConn}
	ErrPoolExhausted       = Error{Code: ErrorCodePoolExhausted}
	ErrEphemeralExhausted  = Error{Code: ErrorCodeEphemeralExhausted}
	ErrCorruptedMessage    = Error{Code: ErrorCodeCorruptedMessage}
	ErrRead                = Error{Code: ErrorCodeRead}
	ErrInvalidAddress      = Error{Code: ErrorCodeInvalidAddress}
)

// Error is an implementation of the error interface
type Error struct {
	Code  string
	Inner error
}

func (e Error) Error() string {
	return fmt.Sprintf("%v: %v", e.Code, e.Inner)
}

// Unwrap implements the errors.Unwrap interface
// Allows calling errors.Is() and errors.As()
func (e Error) Unwrap() error {
	return e.Inner
}

// Wrap wraps the inner error inside the error
func (e Error) Wrap(inner error) error {
	e.Inner = inner
	return e
}

// Is implements the interface needed for calling errors.Is()
func (e Error) Is(err error) bool {
	var clientErr Error
	return errors.As(err, &clientErr) && clientErr.Code == e.Code
}
