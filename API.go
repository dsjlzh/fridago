/*Package fridago : frida golang binding */
package fridago

/*
 #cgo CFLAGS: -g -O0 -w -I.
 #cgo LDFLAGS: -static-libgcc -L${SRCDIR}/libs -lfrida-core -ldl -lm -lrt -lresolv -lpthread -Wl,--export-dynamic
 #include "frida-core.h"

 // The gateway function
 void on_message(FridaScript * script, const gchar * message, GBytes * data, gpointer user_data) {
     onMessage(script, message, data, user_data);
 }
*/
import "C"
import (
	"os"
	"unsafe"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func init() {
	log.SetFormatter(&logrus.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.DebugLevel)
}

func init() {
	log.Info("frida init ...")
	_, err := C.frida_init()
	if err != nil {
		log.WithFields(logrus.Fields{
			"err": err,
		}).Fatal("frida init fail")
	} else {
		log.Info("frida init ok")
	}
}

/*********
 * utils *
 *********/

func IsNullCPointer(ptr unsafe.Pointer) bool {
	return uintptr(ptr) == uintptr(0)
}

/*************
 * Functions *
 *************/

// attach(target)
func Attach(target string) (*Session, error) {
	log.WithFields(logrus.Fields{
		"target": target,
	}).Debug("attach")

	d, _ := GetLocalDevice()
	log.WithFields(logrus.Fields{
		"name": d.Name,
		"id":   d.ID,
		"type": d.Type,
	}).Debug("get local device")

	sess, err := d.Attach(target)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// enumerate_devices()
func EnumerateDevices() ([]*Device, error) {
	dm := GetDeviceManager()
	return dm.EnumerateDevicesSync()
}

// get_device(id, timeout=0)
func GetDevice(id string) (*Device, error) {
	dl, err := GetDeviceMatching(func(d *Device) bool {
		return d.ID == id
	}, 0)

	if len(dl) > 0 {
		return dl[0], nil
	}
	return nil, err
}

// get_device_matching(predicate, timeout=0)
func GetDeviceMatching(predicate func(*Device) bool, timeout int) (dl []*Device, err error) {
	devices, err := EnumerateDevices()
	if err != nil {
		return
	}
	for i, d := range devices {
		if predicate(d) {
			dl = append(dl, devices[i])
		}
	}
	return
}

// get_local_device()
func GetLocalDevice() (*Device, error) {
	dl, err := GetDeviceMatching(func(d *Device) bool {
		return d.Type == DeviceTypeLocal
	}, 0)

	if len(dl) > 0 {
		return dl[0], nil
	}
	return nil, err
}

// get_remote_device()

// get_usb_device(timeout=0)
func GetUsbDevice() (*Device, error) {
	dl, err := GetDeviceMatching(func(d *Device) bool {
		return d.Type == DeviceTypeUsb
	}, 0)

	if len(dl) > 0 {
		return dl[0], nil
	}
	return nil, err
}

// inject_library_blob(target, blob, entrypoint, data)

// inject_library_file(target, path, entrypoint, data)

// kill(target)

// resume(target)

// shutdown()

// spawn(*args, **kwargs)

var deviceManager *DeviceManager

// get_device_manager()
func GetDeviceManager() *DeviceManager {
	if deviceManager == nil {
		deviceManager = new(DeviceManager)
		deviceManager.Init()
	}
	return deviceManager
}
