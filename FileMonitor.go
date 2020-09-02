package fridago

/*
 #include "frida-core.h"
 extern void _on_file_change(FridaFileMonitor * file_monitor, gchar * path, gchar * other_path,
                             GFileMonitorEvent event_type, gpointer user_data);
*/
import "C"
import (
	"unsafe"

	"github.com/sirupsen/logrus"
)

var chFileMonitorEvent *chan *FileMonitorEvent

type FileMonitorEvent struct {
	Path      string
	OtherPath string
	Event     string
}

func (fme *FileMonitorEvent) setEvent(eventType C.GFileMonitorEvent) {
	var et string
	switch eventType {
	case C.G_FILE_MONITOR_EVENT_CHANGED:
		et = "changed"
	case C.G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		et = "changes done hint"
	case C.G_FILE_MONITOR_EVENT_DELETED:
		et = "deleted"
	case C.G_FILE_MONITOR_EVENT_CREATED:
		et = "created"
	case C.G_FILE_MONITOR_EVENT_ATTRIBUTE_CHANGED:
		et = "attribute_changed"
	case C.G_FILE_MONITOR_EVENT_PRE_UNMOUNT:
		et = "pre unmount"
	case C.G_FILE_MONITOR_EVENT_UNMOUNTED:
		et = "unmounted"
	case C.G_FILE_MONITOR_EVENT_MOVED:
		et = "moved"
	case C.G_FILE_MONITOR_EVENT_RENAMED:
		et = "renamed"
	case C.G_FILE_MONITOR_EVENT_MOVED_IN:
		et = "moved in"
	case C.G_FILE_MONITOR_EVENT_MOVED_OUT:
		et = "moved out"
	default:
		et = "unknown"
	}
	fme.Event = et
}

type FileMonitor struct {
	ptr  *C.FridaFileMonitor
	Path string
}

func (fm *FileMonitor) Enable() (err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	C.frida_file_monitor_enable_sync(fm.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return

}

func (fm *FileMonitor) Disable() (err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	C.frida_file_monitor_disable_sync(fm.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return

}

func (fm *FileMonitor) connectSignal(sig string, cb unsafe.Pointer) {
	C.g_signal_connect_data(C.gpointer(fm.ptr),
		C.CString(sig), C.GCallback(cb),
		nil, nil, 0)
}

func (fm *FileMonitor) On(sig string, ch interface{}) (err error) {
	switch sig {
	case "change":
		if v, ok := ch.(chan *FileMonitorEvent); ok {
			chFileMonitorEvent = &v
		}
		fm.connectSignal(sig, unsafe.Pointer(C._on_file_change))
	default:
		err = NewErrorAndLog("FileMonitor: signal unspported")
		log.WithFields(logrus.Fields{
			"signal": sig,
		}).Error(err)
	}
	return
}

func NewFileMonitor(path string) (fm *FileMonitor, err error) {
	monitor := C.frida_file_monitor_new(C.CString(path))
	if IsNullCPointer(unsafe.Pointer(monitor)) {
		err = NewErrorAndLog("FileMonitor: new failed")
		return
	}
	fm = &FileMonitor{
		ptr:  monitor,
		Path: path,
	}
	return
}

//export onFileChange
func onFileChange(fileMonitor *C.FridaFileMonitor, path *C.gchar, otherPath *C.gchar,
	eventType C.GFileMonitorEvent, userData C.gpointer) {
	log.Info("FileMonitor: On file change")
	if chFileMonitorEvent != nil {
		evt := &FileMonitorEvent{
			Path:      C.GoString(path),
			OtherPath: C.GoString(otherPath),
		}
		evt.setEvent(eventType)
		*chFileMonitorEvent <- evt
	}
}
