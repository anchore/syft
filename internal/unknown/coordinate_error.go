package unknown

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

type hasCoordinates interface {
	GetCoordinates() file.Coordinates
}

type CoordinateError struct {
	Coordinates file.Coordinates
	Reason      error
}

var _ error = (*CoordinateError)(nil)

func (u *CoordinateError) Error() string {
	if u.Coordinates.FileSystemID == "" {
		return fmt.Sprintf("%s: %v", u.Coordinates.RealPath, u.Reason)
	}
	return fmt.Sprintf("%s (%s): %v", u.Coordinates.RealPath, u.Coordinates.FileSystemID, u.Reason)
}

// New returns a new CoordinateError unless the reason is a CoordinateError itself, in which case
// reason will be returned directly or if reason is nil, nil will be returned
func New(coords hasCoordinates, reason error) *CoordinateError {
	if reason == nil {
		return nil
	}
	coordinates := coords.GetCoordinates()
	reasonCoordinateError := &CoordinateError{}
	if errors.As(reason, &reasonCoordinateError) {
		// if the reason is already a coordinate error, it is potentially for a different location,
		// so we do not want to surface this location having an error
		return reasonCoordinateError
	}
	return &CoordinateError{
		Coordinates: coordinates,
		Reason:      reason,
	}
}

// Newf returns a new CoordinateError with a reason of an error created from given format and args
func Newf(coords hasCoordinates, format string, args ...any) *CoordinateError {
	return New(coords, fmt.Errorf(format, args...))
}

// Append returns an error joined to the first error/set of errors, with a new CoordinateError appended to the end
func Append(errs error, coords hasCoordinates, reason error) error {
	return Join(errs, New(coords, reason))
}

// Appendf returns an error joined to the first error/set of errors, with a new CoordinateError appended to the end,
// created from the given reason and args
func Appendf(errs error, coords hasCoordinates, format string, args ...any) error {
	return Append(errs, coords, fmt.Errorf(format, args...))
}

// Join joins the provided sets of errors together in a flattened manner, taking into account nested errors created
// from other sources, including errors.Join, multierror.Append, and unknown.Join
func Join(errs ...error) error {
	var out []error
	for _, err := range errs {
		// append errors, de-duplicated
		for _, e := range flatten(err) {
			if containsErr(out, e) {
				continue
			}
			out = append(out, e)
		}
	}
	if len(out) == 1 {
		return out[0]
	}
	if len(out) == 0 {
		return nil
	}
	return errors.Join(out...)
}

// Joinf joins the provided sets of errors together in a flattened manner, taking into account nested errors created
// from other sources, including errors.Join, multierror.Append, and unknown.Join and appending a new error,
// created from the format and args provided -- the error is NOT a CoordinateError
func Joinf(errs error, format string, args ...any) error {
	return Join(errs, fmt.Errorf(format, args...))
}

// IfEmptyf returns a new Errorf-formatted error, only when the provided slice is empty or nil when
// the slice has entries
func IfEmptyf[T any](emptyTest []T, format string, args ...any) error {
	if len(emptyTest) == 0 {
		return fmt.Errorf(format, args...)
	}
	return nil
}

// ExtractCoordinateErrors extracts all coordinate errors returned, and any _additional_ errors in the graph
// are encapsulated in the second, error return parameter
func ExtractCoordinateErrors(err error) (coordinateErrors []CoordinateError, remainingErrors error) {
	remainingErrors = visitErrors(err, func(e error) error {
		if coordinateError, _ := e.(*CoordinateError); coordinateError != nil {
			coordinateErrors = append(coordinateErrors, *coordinateError)
			return nil
		}
		return e
	})
	return coordinateErrors, remainingErrors
}

func flatten(errs ...error) []error {
	var out []error
	for _, err := range errs {
		if err == nil {
			continue
		}
		// turn all errors nested under a coordinate error to individual coordinate errors
		if e, ok := err.(*CoordinateError); ok {
			if e == nil {
				continue
			}
			for _, r := range flatten(e.Reason) {
				out = append(out, New(e.Coordinates, r))
			}
		} else
		// from multierror.Append
		if e, ok := err.(interface{ WrappedErrors() []error }); ok {
			if e == nil {
				continue
			}
			out = append(out, flatten(e.WrappedErrors()...)...)
		} else
		// from errors.Join
		if e, ok := err.(interface{ Unwrap() []error }); ok {
			if e == nil {
				continue
			}
			out = append(out, flatten(e.Unwrap()...)...)
		} else {
			out = append(out, err)
		}
	}
	return out
}

// containsErr returns true if a duplicate error is found
func containsErr(out []error, err error) bool {
	defer func() {
		if err := recover(); err != nil {
			log.Tracef("error comparing errors: %v", err)
		}
	}()
	for _, e := range out {
		if e == err {
			return true
		}
	}
	return false
}

// visitErrors visits every wrapped error. the returned error replaces the provided error, null errors are omitted from
// the object graph
func visitErrors(err error, fn func(error) error) error {
	// unwrap errors from errors.Join
	if errs, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, e := range errs.Unwrap() {
			out = append(out, visitErrors(e, fn))
		}
		// errors.Join omits nil errors and will return nil if all passed errors are nil
		return errors.Join(out...)
	}
	// unwrap errors from multierror.Append -- these also implement Unwrap() error, so check this first
	if errs, ok := err.(interface{ WrappedErrors() []error }); ok {
		var out []error
		for _, e := range errs.WrappedErrors() {
			out = append(out, visitErrors(e, fn))
		}
		// errors.Join omits nil errors and will return nil if all passed errors are nil
		return errors.Join(out...)
	}
	// unwrap singly wrapped errors
	if e, ok := err.(interface{ Unwrap() error }); ok {
		wrapped := e.Unwrap()
		got := visitErrors(wrapped, fn)
		if got == nil {
			return nil
		}
		if wrapped.Error() != got.Error() {
			prefix := strings.TrimSuffix(err.Error(), wrapped.Error())
			return fmt.Errorf("%s%w", prefix, got)
		}
		return err
	}
	return fn(err)
}
