package fridago

/*
 #include "frida-core.h"
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

var (
	chRawMessage chan *rawMessage
	cbs          sync.Map
	reqIDNum     uint64 = 0
)

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

type Message struct {
	Index    uint64
	Msg      interface{}
	Data     []byte
	UserData uintptr
}

type rpcResult struct {
	operation string
	params    []interface{}
	data      []byte
}

type rawMessage struct {
	scriptID uint
	msg      string
	data     []byte
	userData uintptr
}

func init() {
	chRawMessage = make(chan *rawMessage, 100)
	cbs = sync.Map{}
	go msgDispatch()
}

//export onMessage
func onMessage(script *C.FridaScript, message *C.gchar, data *C.GBytes, userData C.gpointer) {
	msg := C.GoString(message)
	id := C.frida_script_get_id(script)
	var dBytes []byte
	if !IsNullCPointer(unsafe.Pointer(data)) {
		var dSize C.ulong
		dBuf := C.g_bytes_get_data(data, &dSize)
		dBytes = C.GoBytes(unsafe.Pointer(dBuf), C.int(dSize))
	}
	// todo: userData
	chRawMessage <- &rawMessage{uint(id), msg, dBytes, 0}
}

func msgDispatch() {
	var index uint64 = 0
	for rawMsg := range chRawMessage {
		if !json.Valid([]byte(rawMsg.msg)) {
			continue
		}
		jsobj := make(map[string]interface{})
		json.Unmarshal([]byte(rawMsg.msg), &jsobj)

		tvpe := jsobj["type"].(string)
		switch tvpe {
		case "log":
			level := jsobj["level"].(string)
			text := jsobj["payload"].(string)
			/* todo: log_handler */
			log.WithFields(logrus.Fields{
				"level": level,
				"text":  text,
			}).Info("Logger")
		case "send":
			payload, isList := jsobj["payload"].([]interface{})
			if isList && payload[0].(string) == "frida:rpc" {
				reqID := payload[1].(string)
				key := fmt.Sprintf("%d_%s", rawMsg.scriptID, reqID)
				cbv, _ := cbs.Load(key)
				if cb, ok := cbv.(chan *rpcResult); ok {
					operation := payload[2].(string)
					cb <- &rpcResult{operation, payload[3:], rawMsg.data}
				}
			} else {
				key := fmt.Sprintf("%d_%s", rawMsg.scriptID, "message")
				cbv, _ := cbs.Load(key)
				if cb, ok := cbv.(chan *Message); ok {
					cb <- &Message{index, jsobj["payload"], rawMsg.data, 0}
				}
				index++
			}
		}
	}
}

func (scr *Script) connectSignal(sig string, cb unsafe.Pointer) {
	C.g_signal_connect_data(C.gpointer(scr.ptr),
		C.CString(sig), C.GCallback(cb),
		nil, nil, 0)
}

func (scr *Script) On(sig string, cb chan *Message) (err error) {
	switch sig {
	case "message":
		key := fmt.Sprintf("%d_%s", scr.ID, sig)
		cbs.Store(key, cb)
	default:
		err = NewErrorAndLog("Script: signal unspported")
		log.WithFields(logrus.Fields{
			"signal": sig,
		}).Error(err)
	}
	return
}

func (scr *Script) UnLoad() error {
	var gerr *C.GError
	C.frida_script_unload_sync(scr.ptr, &gerr)
	if gerr != nil {
		return NewErrorFromGError(gerr)
	}
	C.frida_unref(C.gpointer(scr.ptr))
	scr.ptr = nil
	return nil
}

func (scr *Script) Load() error {
	var gerr *C.GError
	C.frida_script_load_sync(scr.ptr, &gerr)
	if gerr != nil {
		return NewErrorFromGError(gerr)
	}
	return nil
}

func (scr *Script) Eternalize() error {
	var gerr *C.GError
	C.frida_script_eternalize_sync(scr.ptr, &gerr)
	if gerr != nil {
		return NewErrorFromGError(gerr)
	}
	return nil
}

func (scr *Script) Post(message string, data []byte) (err error) {
	var gerr *C.GError
	if gData, ok := GoBytesToGBytes(data); ok {
		C.frida_script_post_sync(scr.ptr, C.CString(message), gData, &gerr)
	}
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return nil
}

func (scr *Script) RpcCall(js_name string, args ...string) (result interface{}, err error) {
	reqID := fmt.Sprintf("%s_%d", "req", atomic.AddUint64(&reqIDNum, 1))
	key := fmt.Sprintf("%d_%s", scr.ID, reqID)
	cb := make(chan *rpcResult, 1)
	defer close(cb)
	cbs.Store(key, cb)

	request := []string{"frida:rpc", reqID, "call", js_name}
	for i, _ := range args {
		request = append(request, args[i])
	}
	b, err := json.Marshal(request)
	if err != nil {
		return
	}
	err = scr.Post(string(b), make([]byte, 0))
	if err != nil {
		return
	}

	select {
	case <-time.After(60 * time.Second):
		err = NewErrorAndLog("Script: rpc call timeout")
	case res := <-cb:
		if res.operation == "ok" {
			if len(res.data) > 0 {
				result = res.data
			} else {
				result = res.params[0]
			}
		} else {
			err = NewErrorAndLog(res.params[0].(string))
		}
	}
	return
}
