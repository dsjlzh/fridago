package fridago

/*
 #include "frida-core.h"
*/
import "C"
import (
	"github.com/sirupsen/logrus"
)

type Session struct {
	ptr *C.FridaSession
	Dev *Device
	Pid uint
}

func (sess *Session) IsDetached() bool {
	return GbooleanToGoBool(C.frida_session_is_detached(sess.ptr))
}

func (sess *Session) CreateScriptSync(name string, source string, runtime ...uint) (s *Script, err error) {
	log.WithFields(logrus.Fields{
		"name": name,
		// "source": source,
	}).Debug("Session: create script ...")

	return NewScript(sess, name, source, C.FRIDA_SCRIPT_RUNTIME_V8)
}

func (sess *Session) CreateScriptFromBytesSync(name string, bytes []byte, runtime ...uint) (s *Script, err error) {
	log.WithFields(logrus.Fields{
		"name": name,
		// "source": bytes,
	}).Debug("Session: create script from bytes ...")

	return NewScript(sess, name, bytes, C.FRIDA_SCRIPT_RUNTIME_DUK)
}

func (sess *Session) Detach() (err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	C.frida_session_detach_sync(sess.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
		return
	}
	C.frida_unref(C.gpointer(sess.ptr))
	sess.ptr = nil
	return
}

func (sess *Session) EnableChildGating() (err error) {
	return sess.doToggle("enable_child_gating")
}

func (sess *Session) DisableChildGating() (err error) {
	return sess.doToggle("disable_child_gating")
}

func (sess *Session) EnableDebugger(port uint) (err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	C.frida_session_enable_debugger_sync(sess.ptr, C.guint16(port), cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return
}

func (sess *Session) DisableDebugger() (err error) {
	return sess.doToggle("disable_debugger")
}

func (sess *Session) EnableJit() (err error) {
	return sess.doToggle("enable_git")
}

func (sess *Session) doToggle(onOff string) (err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	switch onOff {
	case "enable_child_gating":
		C.frida_session_enable_child_gating_sync(sess.ptr, cancel, &gerr)
	case "disable_child_gating":
		C.frida_session_disable_child_gating_sync(sess.ptr, cancel, &gerr)
	case "disable_debugger":
		C.frida_session_disable_debugger_sync(sess.ptr, cancel, &gerr)
	case "enable_git":
		C.frida_session_enable_jit_sync(sess.ptr, cancel, &gerr)
	}
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return
}

// todo:
// compile_script

func NewSession(dev *Device, fs *C.FridaSession) (s *Session, err error) {
	s = &Session{
		ptr: fs,
		Dev: dev,
		Pid: uint(C.frida_session_get_pid(fs)),
	}
	return
}
