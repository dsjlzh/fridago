package fridago

/*
 #include "frida-core.h"
 extern void on_message(FridaScript * script, const gchar * message, GBytes * data, gpointer user_data);
*/
import "C"
import (
	"unsafe"

	"github.com/sirupsen/logrus"
)

type Session struct {
	ptr *C.FridaSession
	Dev *Device
	Pid uint
}

func (sess *Session) commCreateScript(name string, source interface{}, runtime []uint) (s *Script, err error) {
	opts := C.frida_script_options_new()
	defer func() {
		C.frida_unref(C.gpointer(opts))
		opts = nil
	}()

	C.frida_script_options_set_name(opts, C.CString(name))
	if len(runtime) > 0 {
		log.Warn("Session: runtime parameter unsupported yet")
	}

	var (
		gerr   *C.GError
		script *C.FridaScript
	)
	switch src := source.(type) {
	case string:
		C.frida_script_options_set_runtime(opts, C.FRIDA_SCRIPT_RUNTIME_V8)
		script = C.frida_session_create_script_sync(sess.ptr, C.CString(src), opts, &gerr)
	case []byte:
		if gBytes, ok := GoBytesToGBytes(src); ok {
			script = C.frida_session_create_script_from_bytes_sync(sess.ptr, gBytes, opts, &gerr)
		}
	}

	if gerr != nil {
		err = NewErrorFromGError(gerr)
	} else if !IsNullCPointer(unsafe.Pointer(script)) {
		s = &Script{
			ptr:  script,
			ID:   uint(C.frida_script_get_id(script)),
			Name: name,
		}
		// s.connectSignal("destroyed", unsafe.Pointer(C.on_destroyed))
		s.connectSignal("message", unsafe.Pointer(C.on_message))
	}
	return
}

func (sess *Session) CreateScriptSync(name string, source string, runtime ...uint) (s *Script, err error) {
	log.WithFields(logrus.Fields{
		"name": name,
		// "source": source,
	}).Debug("Session: create script ...")

	return sess.commCreateScript(name, source, runtime)
}

func (sess *Session) CreateScriptFromBytesSync(name string, bytes []byte, runtime ...uint) (s *Script, err error) {
	log.WithFields(logrus.Fields{
		"name": name,
		// "source": bytes,
	}).Debug("Session: create script from bytes ...")

	return sess.commCreateScript(name, bytes, runtime)
}

func (sess *Session) Detach() {
	C.frida_session_detach_sync(sess.ptr)
	C.frida_unref(C.gpointer(sess.ptr))
	sess.ptr = nil
}

func (sess *Session) EnableChildGating() (err error) {
	var gerr *C.GError
	C.frida_session_enable_child_gating_sync(sess.ptr, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return
}

func (sess *Session) DisableChildGating() (err error) {
	var gerr *C.GError
	C.frida_session_disable_child_gating_sync(sess.ptr, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return
}
