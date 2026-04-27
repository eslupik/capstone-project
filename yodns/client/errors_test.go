package client

import (
	"errors"
	"testing"
)

func Test_ErrorsIs_DoesUnwrap(t *testing.T) {
	innerErr := errors.New("uh oh")
	customErr := ErrDial.Wrap(innerErr)

	if !errors.Is(customErr, innerErr) {
		t.Errorf("Expected errors.Is(%v, %v) to be true", customErr, innerErr)
	}
}

func Test_ErrorsIs_OuterErrorErrorCodeEqual_ExpectTrue(t *testing.T) {
	customErr1 := ErrDial.Wrap(errors.New("uh oh"))
	customErr2 := ErrDial.Wrap(errors.New("oh uh"))

	if !errors.Is(customErr1, customErr2) {
		t.Errorf("Expected errors.Is(%v, %v) to be true", customErr1, customErr2)
	}
}

func Test_UseErrorsIs_DifferentErrorCodes_ExpectFalse(t *testing.T) {
	customErr1 := ErrDial.Wrap(errors.New("uh oh"))
	customErr2 := ErrGracePeriodBegun.Wrap(errors.New("uh oh"))

	if errors.Is(customErr1, customErr2) {
		t.Errorf("Expected errors.Is(%v, %v) to be false", customErr1, customErr2)
	}
}
