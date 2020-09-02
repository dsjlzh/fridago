package fridago

/*
 #include "frida-core.h"
*/
import "C"
import (
	"errors"
)

// Errors
var (
	ErrNoDevice               = errors.New("No Device")
	ErrAddressInUse           = errors.New("Address In Use")
	ErrExecutableNotFound     = errors.New("Executable Not Found")
	ErrExecutableNotSupported = errors.New("Executable Not Supported")
	ErrInvalidArgument        = errors.New("Invalid Argument")
	ErrInvalidOperation       = errors.New("Invallid Operation")
	ErrNotSupported           = errors.New("Not Supported")
	ErrPermissionDenied       = errors.New("Permission Denied")
	ErrProcessNotFound        = errors.New("Process Not Found")
	ErrProcessNotResponding   = errors.New("Process Not Responding")
	ErrProtocolError          = errors.New("Protocol Error")
	ErrServerNotRunning       = errors.New("Server Not Running")
	ErrTimedOut               = errors.New("Timeout")
	ErrTransportError         = errors.New("Transport Error")
)

type GError struct {
	Msg  string
	Code int
}

func (err *GError) Error() string {
	return err.Msg
}

func (err *GError) New(gerr *C.GError) {
	err.Msg = C.GoString(gerr.message)
	err.Code = int(gerr.code)
}

func NewErrorFromGError(gerr *C.GError) error {
	e := &GError{}
	e.New(gerr)
	log.Error(e)
	return e
}

func NewErrorAndLog(errMsg string) error {
	e := errors.New(errMsg)
	log.Error(e)
	return e
}
