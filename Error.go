package fridago

/*
 #include "frida-core.h"
*/
import "C"
import (
	"errors"
)
// Errors
// AddressInUseError
// ExecutableNotFoundError
// ExecutableNotSupportedError
// InvalidArgumentError
// InvalidOperationError
// NotSupportedError
// PermissionDeniedError
// ProcessNotFoundError
// ProcessNotRespondingError
// ProtocolError
// ServerNotRunningError
// TimedOutError
// TransportError

type GError struct {
	Msg string
	Code int
}

func (err *GError) Error() string {
	return err.Msg
}

func (err *GError) New(gerr *C.GError) {
	err.Msg = C.GoString(gerr.message)
	err.Code = int(gerr.code)
}

var (
	ErrNoDevice = errors.New("No Device")
)
