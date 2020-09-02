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

func (dm *DeviceManager) init() (err error) {
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
		fd := C.frida_device_list_get(devices, C.int(i))
		d, _ := NewDevice(fd)
		log.WithFields(logrus.Fields{
			"name": d.Name,
			"id":   d.ID,
			"type": d.Type,
		}).Debug("DeviceManager: enumerate device")
		dl = append(dl, d)
	}
	return
}

func (dm *DeviceManager) GetDeviceById(id string, timeout int) (d *Device, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	dev := C.frida_device_manager_get_device_by_id_sync(dm.ptr, C.CString(id), C.gint(timeout), cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
		return
	}
	return NewDevice(dev)
}

func (dm *DeviceManager) GetDeviceByType(dtype C.FridaDeviceType, timeout int) (d *Device, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	dev := C.frida_device_manager_get_device_by_type_sync(dm.ptr, dtype, C.gint(timeout), cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
		return
	}
	return NewDevice(dev)
}

// todo:
// add_remote_device
// remove_remote_device

func NewDeviceManager() (dm *DeviceManager, err error) {
	dm = new(DeviceManager)
	err = dm.init()
	return
}
