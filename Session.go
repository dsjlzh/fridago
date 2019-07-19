package fridago

/*
 #include "frida-core.h"
*/
import "C"
import (
	"errors"
	"unsafe"

	"github.com/sirupsen/logrus"
)

type Session struct {
	ptr *C.FridaSession
	Dev *Device
	Pid uint
}

func (sess *Session) CreateScriptSync(name string, source string, runtime ...uint) (s *Script, err error) {
	log.WithFields(logrus.Fields{
		"name": name,
		// "source": source,
	}).Debug("Session: create script ...")

	opts := C.frida_script_options_new()
	defer func() {
		C.frida_unref(C.gpointer(opts))
		opts = nil
	}()

	C.frida_script_options_set_name(opts, C.CString(name))
	if len(runtime) > 0 {
		return nil, errors.New("Session: runtime parameter unsuppored")
	} else {
		C.frida_script_options_set_runtime(opts, C.FRIDA_SCRIPT_RUNTIME_V8)
	}

	var gerr *C.GError
	script := C.frida_session_create_script_sync(sess.ptr, C.CString(source), opts, &gerr)
	if gerr != nil || IsNullCPointer(unsafe.Pointer(script)) {
		return nil, errors.New("Session: create script error")
	}
	s = &Script{
		ptr:  script,
		ID:   uint(C.frida_script_get_id(script)),
		Name: name,
	}
	return
}

func (sess *Session) Detach() {
	C.frida_session_detach_sync(sess.ptr)
	C.frida_unref(C.gpointer(sess.ptr))
	sess.ptr = nil
}

// Todo: enable_child_gating()
// Todo: disable_child_gating()
