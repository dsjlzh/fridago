package fridago

/*
 #include "frida-core.h"
 extern void on_message(FridaScript * script, const gchar * message, GBytes * data, gpointer user_data);
*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

var cbs = sync.Map{}

const (
	SCRIPT_RUNTIME_DEFAULT = uint(C.FRIDA_SCRIPT_RUNTIME_DEFAULT)
	SCRIPT_RUNTIME_DUK     = uint(C.FRIDA_SCRIPT_RUNTIME_DUK)
	SCRIPT_RUNTIME_V8      = uint(C.FRIDA_SCRIPT_RUNTIME_V8)
)

type Script struct {
	ptr  *C.FridaScript
	ID   uint
	Name string
}

//export onMessage
func onMessage(script *C.FridaScript, message *C.gchar, data *C.GBytes, userData C.gpointer) {
	log.Debug("callback on message")
	var dBytes []byte
	if !IsNullCPointer(unsafe.Pointer(data)) {
		var dSize C.ulong
		dBuf := C.g_bytes_get_data(data, &dSize)
		dBytes = C.GoBytes(unsafe.Pointer(dBuf), C.int(dSize))
	}

	id := C.frida_script_get_id(script)
	key := fmt.Sprintf("%d_%s", id, "message")
	fv, _ := cbs.Load(key)
	/* Type assertions */
	if f, ok := fv.(func(string, []byte)); ok {
		go f(C.GoString(message), dBytes)
	}
}

func (scr *Script) connectSignal(sig string, cb unsafe.Pointer) {
	C.g_signal_connect_data(C.gpointer(scr.ptr),
		C.CString(sig), C.GCallback(cb),
		nil, nil, 0)
}

func (scr *Script) On(sig string, gocb func(string, []byte)) error {
	var ccb unsafe.Pointer
	switch sig {
	case "message":
		ccb = unsafe.Pointer(C.on_message)
	default:
		return errors.New("Script: signal unspported")
	}

	key := fmt.Sprintf("%d_%s", scr.ID, sig)
	cbs.Store(key, gocb)
	scr.connectSignal(sig, ccb)
	return nil
}

func (scr *Script) UnLoad() error {
	var gerr *C.GError
	C.frida_script_unload_sync(scr.ptr, &gerr)
	if gerr != nil {
		return errors.New("Script: unload error")
	}
	C.frida_unref(C.gpointer(scr.ptr))
	scr.ptr = nil
	return nil
}

func (scr *Script) Load() error {
	var gerr *C.GError
	C.frida_script_load_sync(scr.ptr, &gerr)
	if gerr != nil {
		return errors.New("Script: load error")
	}
	return nil
}

// Todo: eternalize()
// Todo: post()
