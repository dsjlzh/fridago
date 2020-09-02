/*Package fridago : frida golang binding */
package fridago

/*
 #cgo CFLAGS: -g -O2 -w -I. -I${SRCDIR}/libs
 #cgo LDFLAGS: -static-libgcc -L${SRCDIR}/libs -lfrida-core -ldl -lm -lrt -lresolv -lpthread -Wl,--export-dynamic
 #include "frida-core.h"

 // The gateway function
 void _on_message(FridaScript * script, const gchar * message, GBytes * data, gpointer user_data) {
     onMessage(script, message, data, user_data);
 }
 void _on_spawn_added(FridaDevice * device, FridaSpawn * spawn, gpointer user_data) {
     onSpawnAdded(device, spawn, user_data);
 }
 void _on_child_added(FridaDevice * device, FridaChild * child, gpointer user_data) {
     onChildAdded(device, child, user_data);
 }
 void _on_output(FridaDevice * device, guint pid, gint fd, GBytes * data, gpointer user_data) {
     onOutput(device, pid, fd, data, user_data);
 }
 void _on_file_change(FridaFileMonitor * file_monitor, gchar * path, gchar * other_path,
                      GFileMonitorEvent event_type, gpointer user_data) {
     onFileChange(file_monitor, path, other_path, event_type, user_data);
 }
*/
import "C"
import (
	"os"
	"time"
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

func GoBytesToGBytes(bytes []byte) (g *C.GBytes, ok bool) {
	size := len(bytes)
	g = C.g_bytes_new_take(C.gpointer(C.CBytes(bytes)), C.ulong(size))
	if IsNullCPointer(unsafe.Pointer(g)) {
		return nil, false
	}
	gSize := C.g_bytes_get_size(g)
	if int(gSize) != size {
		return nil, false
	}

	return g, true
}

func GStringsToGoStrings(gs **C.gchar, length C.gint) (strs []string, ok bool) {
	len := int(length)
	if len > 0 {
		arr := (*[1 << 30]*C.gchar)(unsafe.Pointer(gs))
		strs = make([]string, len)
		for i := 0; i < len; i++ {
			strs[i] = C.GoString(arr[i])
		}
		ok = true
	}
	return
}

func GbooleanToGoBool(gb C.gboolean) bool {
	return int(gb) != 0
}

/*************
 * Functions *
 *************/

func Attach(target string) (sess *Session, err error) {
	log.WithFields(logrus.Fields{
		"target": target,
	}).Debug("attach")

	d, _ := GetLocalDevice()
	log.WithFields(logrus.Fields{
		"name": d.Name,
		"id":   d.ID,
		"type": d.Type,
	}).Debug("get local device")

	p, err := d.FindProcessByNameSync(target, 10)
	if err != nil {
		return
	}
	return d.Attach(p.Pid)
}

func EnumerateDevices() ([]*Device, error) {
	dm := GetDeviceManager()
	return dm.EnumerateDevicesSync()
}

func GetDevice(id string) (*Device, error) {
	dm := GetDeviceManager()
	return dm.GetDeviceById(id, 10)
}

func GetDeviceMatching(predicate func(*Device) bool, timeout time.Duration) (dl []*Device, err error) {
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

func GetLocalDevice() (*Device, error) {
	dm := GetDeviceManager()
	return dm.GetDeviceByType(C.FRIDA_DEVICE_TYPE_LOCAL, 10)
}

func GetRemoteDevice() (*Device, error) {
	dm := GetDeviceManager()
	return dm.GetDeviceByType(C.FRIDA_DEVICE_TYPE_REMOTE, 10)
}

func GetUsbDevice() (*Device, error) {
	dm := GetDeviceManager()
	return dm.GetDeviceByType(C.FRIDA_DEVICE_TYPE_USB, 10)
}

// inject_library_blob(target, blob, entrypoint, data)
// inject_library_file(target, path, entrypoint, data)
// kill(target)
// resume(target)
// shutdown()
// spawn(*args, **kwargs)

var deviceManager *DeviceManager

func GetDeviceManager() *DeviceManager {
	if deviceManager == nil {
		deviceManager, _ = NewDeviceManager()
	}
	return deviceManager
}
