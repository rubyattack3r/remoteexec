// Package errs classifies operational failures so callers can report them
// consistently across validation, transport, and cleanup boundaries.
package errs

import (
	"errors"
	"fmt"
)

// Category is the stable classification of an operational failure.
type Category string

const (
	Validation     Category = "validation"
	Authentication Category = "authentication"
	Authorization  Category = "authorization"
	Reachability   Category = "reachability"
	Conflict       Category = "conflict"
	Execution      Category = "execution"
	Cleanup        Category = "cleanup"
)

// Error pairs a category with the underlying failure.
type Error struct {
	Category Category
	Err      error
}

func (e *Error) Error() string { return string(e.Category) + ": " + e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

// New builds a classified error with a formatted message.
func New(category Category, format string, args ...any) error {
	return &Error{Category: category, Err: fmt.Errorf(format, args...)}
}

// Wrap classifies an existing error.
func Wrap(category Category, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Category: category, Err: err}
}

// CategoryOf walks the error chain and returns the first classification,
// defaulting to execution for unclassified errors.
func CategoryOf(err error) Category {
	for err != nil {
		var classified *Error
		if errors.As(err, &classified) {
			return classified.Category
		}
		err = errors.Unwrap(err)
	}
	return Execution
}
