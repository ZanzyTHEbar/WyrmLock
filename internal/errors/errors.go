// Package errors provides structured error handling for the application
package errors

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/ZanzyTHEbar/assert-lib"
	"github.com/ZanzyTHEbar/errbuilder-go"
)

// Standard error codes based on gRPC error code specification
const (
	// Base value for custom codes
	wyrmlockCodeBase = 1000

	// Custom error codes
	CodePrivilegeOperation = wyrmlockCodeBase + iota
	CodeProcessVerification
	CodeProcessCommunication
	CodeSocketOperation
	CodeConfigOperation
	CodeAuthOperation
	CodeMonitorOperation
	CodeHelperOperation
	CodeHashComputation
	CodeIPCOperation
	CodeMemoryViolation
)

// Common errors
var (
	ErrInvalidArgument     = errors.New("invalid argument")
	ErrPermissionDenied    = errors.New("permission denied")
	ErrNotFound            = errors.New("not found")
	ErrAlreadyExists       = errors.New("already exists")
	ErrUnauthenticated     = errors.New("unauthenticated")
	ErrInternal            = errors.New("internal error")
	ErrPrivilegeOperation  = errors.New("privilege operation error")
	ErrProcessVerification = errors.New("process verification error")
	ErrSocketOperation     = errors.New("socket operation error")
	ErrMonitorOperation    = errors.New("process monitor error")
)

// GlobalAssertHandler is a global assertion handler
var GlobalAssertHandler *assert.AssertHandler

// Initialize the global assertion handler
func init() {
	GlobalAssertHandler = assert.NewAssertHandler()
}

// New creates a new error with the given message
func New(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.CodeUnknown).
		WithMsg(msg)
}

// Newf creates a new formatted error
func Newf(format string, args ...interface{}) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.CodeUnknown).
		WithMsg(fmt.Sprintf(format, args...))
}

// Wrap wraps an existing error with additional context
func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}

	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.CodeUnknown).
		WithMsg(msg).
		WithCause(err)
}

// Wrapf wraps an existing error with formatted context
func Wrapf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}

	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.CodeUnknown).
		WithMsg(fmt.Sprintf(format, args...)).
		WithCause(err)
}

// Is checks if an error is a specific error
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

// Assert performs an assertion with the global handler
func Assert(ctx context.Context, condition bool, msg string) {
	GlobalAssertHandler.Assert(ctx, condition, msg)
}

// AssertNotNil asserts that the given value is not nil
func AssertNotNil(ctx context.Context, val interface{}, msg string) {
	GlobalAssertHandler.NotNil(ctx, val, msg)
}

// AssertNoError asserts that the given error is nil
func AssertNoError(ctx context.Context, err error, msg string) {
	GlobalAssertHandler.NoError(ctx, err, msg)
}

// GetCaller returns the file name and line number of the calling function
func GetCaller(skip int) string {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return "unknown"
	}
	return fmt.Sprintf("%s:%d", file, line)
}

// ValidationError creates a validation error
func ValidationError(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.CodeInvalidArgument).
		WithMsg(msg)
}

// PrivilegeError returns a privilege-related error
func PrivilegeError(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.ErrCode(CodePrivilegeOperation)).
		WithMsg(msg).
		WithCause(ErrPrivilegeOperation)
}

// ProcessVerificationError returns a process verification error
func ProcessVerificationError(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.ErrCode(CodeProcessVerification)).
		WithMsg(msg).
		WithCause(ErrProcessVerification)
}

// IPCError returns an IPC-related error
func IPCError(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.ErrCode(CodeIPCOperation)).
		WithMsg(fmt.Sprintf("IPC operation error: %s", msg))
}

// HelperError returns a helper-related error
func HelperError(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.ErrCode(CodeHelperOperation)).
		WithMsg(fmt.Sprintf("helper operation error: %s", msg))
}

// SocketError returns a socket-related error
func SocketError(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.ErrCode(CodeSocketOperation)).
		WithMsg(msg).
		WithCause(ErrSocketOperation)
}

// AuthError returns an authentication-related error
func AuthError(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.ErrCode(CodeAuthOperation)).
		WithMsg(msg)
}

// ConfigError returns a configuration-related error
func ConfigError(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.ErrCode(CodeConfigOperation)).
		WithMsg(msg)
}

// HashError returns a hash computation related error
func HashError(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.ErrCode(CodeHashComputation)).
		WithMsg(msg)
}

// MonitorError returns a process monitor related error
func MonitorError(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.ErrCode(CodeMonitorOperation)).
		WithMsg(msg).
		WithCause(ErrMonitorOperation)
}

// WithDetails attaches structured details to an error
func WithDetails(err error, details errbuilder.ErrorMap) error {
	if err == nil {
		return nil
	}

	errDetails := errbuilder.NewErrDetails(details)
	return errbuilder.NewErrBuilder().
		WithCause(err).
		WithDetails(errDetails)
}

// WithCode creates a new error with a specific error code
func WithCode(err error, code errbuilder.ErrCode) error {
	if err == nil {
		return nil
	}
	
	return errbuilder.NewErrBuilder().
		WithCode(code).
		WithCause(err)
}

// NotFound creates a "not found" error with the given message
func NotFound(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.CodeNotFound).
		WithMsg(msg).
		WithCause(ErrNotFound)
}

// AlreadyExists creates an "already exists" error with the given message
func AlreadyExists(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.CodeAlreadyExists).
		WithMsg(msg).
		WithCause(ErrAlreadyExists)
}

// PermissionDenied creates a permission denied error
func PermissionDenied(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.CodePermissionDenied).
		WithMsg(msg).
		WithCause(ErrPermissionDenied)
}

// Unauthenticated creates an unauthenticated error
func Unauthenticated(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.CodeUnauthenticated).
		WithMsg(msg).
		WithCause(ErrUnauthenticated)
}

// Internal creates an internal error
func Internal(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.CodeInternal).
		WithMsg(msg).
		WithCause(ErrInternal)
}

// MemoryViolation creates a memory violation error
func MemoryViolation(msg string) error {
	return errbuilder.NewErrBuilder().
		WithCode(errbuilder.ErrCode(CodeMemoryViolation)).
		WithMsg(msg)
}
