package fridago

/*
 #include "frida-core.h"
*/
import "C"
import (
	"github.com/sirupsen/logrus"
)

type DeviceManager struct {
	ptr *C.FridaDeviceManager
}

// GetLocalDevice ...

func (dm *DeviceManager) Init() (err error) {
	log.Info("DeviceManager: new ...")
	manager, err := C.frida_device_manager_new()
	if err != nil {
		log.WithFields(logrus.Fields{
			"err": err,
		}).Error("DeviceManager: new fail")
	} else {
		log.Info("DeviceManager: new ok")
		dm.ptr = manager
	}
	return
}

func (dm *DeviceManager) Close() (err error) {
	log.Info("DeviceManager: Close")
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	C.frida_device_manager_close_sync(dm.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
		return
	}

	C.frida_unref(C.gpointer(dm.ptr))
	dm.ptr = nil
	return
}

func (dm *DeviceManager) EnumerateDevicesSync() (dl []*Device, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	devices := C.frida_device_manager_enumerate_devices_sync(dm.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
		return
	}

	defer func() {
		C.frida_unref(C.gpointer(devices))
		devices = nil
	}()

	n := int(C.frida_device_list_size(devices))
	for i := 0; i < n; i++ {
		device := C.frida_device_list_get(devices, C.int(i))
		d := &Device{
			ptr:  device,
			Name: C.GoString(C.frida_device_get_name(device)),
			ID:   C.GoString(C.frida_device_get_id(device)),
			Type: uint(C.frida_device_get_dtype(device)),
		}
		log.WithFields(logrus.Fields{
			"name": d.Name,
			"id":   d.ID,
			"type": d.Type,
		}).Debug("DeviceManager: add device")
		dl = append(dl, d)
	}
	return
}
