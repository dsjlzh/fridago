package fridago

/*
 #include "frida-core.h"
 extern void _on_spawn_added(FridaDevice * device, FridaSpawn * spawn, gpointer user_data);
 extern void _on_child_added(FridaDevice * device, FridaChild * child, gpointer user_data);
 extern void _on_output(FridaDevice * device, guint pid, gint fd, GBytes * data, gpointer user_data);
*/
import "C"
import (
	"unsafe"

	"github.com/sirupsen/logrus"
)

const (
	DeviceTypeLocal  = uint(C.FRIDA_DEVICE_TYPE_LOCAL)
	DeviceTypeRemote = uint(C.FRIDA_DEVICE_TYPE_REMOTE)
	DeviceTypeUsb    = uint(C.FRIDA_DEVICE_TYPE_USB)
)

var (
	chChildAdd *chan *Child
	chSpawnAdd *chan *Spawn
	chOutput   *chan *Output
)

type Output struct {
	Pid  uint
	Fd   int
	Data []byte
}

type Device struct {
	ptr  *C.FridaDevice
	Name string
	ID   string
	Type uint
	// Icon *Icon
}

func (d *Device) IsLost() bool {
	return GbooleanToGoBool(C.frida_device_is_lost(d.ptr))
}

func (d *Device) Attach(pid uint) (s *Session, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	sess := C.frida_device_attach_sync(d.ptr, C.uint(pid), cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	} else {
		s, err = NewSession(d, sess)
	}
	return
}

func (d *Device) Spawn(program string) (pid uint, err error) {
	var gerr *C.GError
	opts := C.frida_spawn_options_new() // todo: handle more options
	defer func() {
		C.frida_unref(C.gpointer(opts))
		opts = nil
	}()

	cancel := C.g_cancellable_new()
	pid = uint(C.frida_device_spawn_sync(d.ptr, C.CString(program), opts, cancel, &gerr))
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return
}

func (d *Device) Resume(pid uint) (err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	C.frida_device_resume_sync(d.ptr, C.guint(pid), cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return
}

func (d *Device) Kill(pid uint) (err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	C.frida_device_kill_sync(d.ptr, C.guint(pid), cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return
}

func (d *Device) EnumerateProcessesSync() (pl []*Process, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	processes := C.frida_device_enumerate_processes_sync(d.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
		return
	}
	if IsNullCPointer(unsafe.Pointer(processes)) {
		err = NewErrorAndLog("Device: enumerate processes error")
		return
	}

	defer func() {
		C.frida_unref(C.gpointer(processes))
		processes = nil
	}()

	n := int(C.frida_process_list_size(processes))
	for i := 0; i < n; i++ {
		fp := C.frida_process_list_get(processes, C.int(i))
		p, _ := NewProcess(fp)
		log.WithFields(logrus.Fields{
			"name": p.Name,
			"pid":  p.Pid,
		}).Debug("enumerate process")
		pl = append(pl, p)
	}
	return
}

func (d *Device) FindProcessByPidSync(pid uint) (p *Process, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	proc := C.frida_device_find_process_by_pid_sync(d.ptr, C.guint(pid), cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
		return
	}
	if IsNullCPointer(unsafe.Pointer(proc)) {
		err = NewErrorAndLog("Device: process not found")
		return
	}
	return NewProcess(proc)
}

func (d *Device) FindProcessByNameSync(name string, timeout int) (p *Process, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	proc := C.frida_device_find_process_by_name_sync(d.ptr, C.CString(name), C.gint(timeout), cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
		return
	}
	if IsNullCPointer(unsafe.Pointer(proc)) {
		err = NewErrorAndLog("Device: process not found")
		return
	}
	return NewProcess(proc)
}

func (d *Device) EnumerateApplicationsSync() (al []*Application, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	applications := C.frida_device_enumerate_applications_sync(d.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
		return
	}
	if IsNullCPointer(unsafe.Pointer(applications)) {
		err = NewErrorAndLog("Device: enumerate applications error")
		return
	}

	defer func() {
		C.frida_unref(C.gpointer(applications))
		applications = nil
	}()

	n := int(C.frida_application_list_size(applications))
	for i := 0; i < n; i++ {
		fa := C.frida_application_list_get(applications, C.int(i))
		a, _ := NewApplication(fa)
		log.WithFields(logrus.Fields{
			"name":       a.Name,
			"identifier": a.Identifier,
			"pid":        a.Pid,
		}).Debug("Device: enumerate application")
		al = append(al, a)
	}
	return
}

func (d *Device) GetFrontmostApplicationSync() (a *Application, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	app := C.frida_device_get_frontmost_application_sync(d.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
		return
	}
	if IsNullCPointer(unsafe.Pointer(app)) {
		err = NewErrorAndLog("Device: get frontmost application failed")
		return
	}
	a, err = NewApplication(app)
	return
}

func (d *Device) EnableSpawnGating() (err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	C.frida_device_enable_spawn_gating_sync(d.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return
}

func (d *Device) DisableSpawnGating() (err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	C.frida_device_disable_spawn_gating_sync(d.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	return
}

func (d *Device) connectSignal(sig string, cb unsafe.Pointer) {
	C.g_signal_connect_data(C.gpointer(d.ptr),
		C.CString(sig), C.GCallback(cb),
		nil, nil, 0)
}

func (d *Device) On(sig string, ch interface{}) (err error) {
	switch sig {
	case "child-added":
		if v, ok := ch.(chan *Child); ok {
			chChildAdd = &v
		}
		d.connectSignal(sig, unsafe.Pointer(C._on_child_added))
	case "spawn-added":
		if v, ok := ch.(chan *Spawn); ok {
			chSpawnAdd = &v
		}
		d.connectSignal(sig, unsafe.Pointer(C._on_spawn_added))
	case "output":
		if v, ok := ch.(chan *Output); ok {
			chOutput = &v
		}
		d.connectSignal(sig, unsafe.Pointer(C._on_output))
	default:
		err = NewErrorAndLog("Device: signal unspported")
		log.WithFields(logrus.Fields{
			"signal": sig,
		}).Error(err)
	}
	return
}

func (d *Device) EnumeratePendingSpawnSync() (sl []*Spawn, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	spawns := C.frida_device_enumerate_pending_spawn_sync(d.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	if IsNullCPointer(unsafe.Pointer(spawns)) {
		err = NewErrorAndLog("Device: enumerate pending spawn error")
		return
	}

	defer func() {
		C.frida_unref(C.gpointer(spawns))
		spawns = nil
	}()

	n := int(C.frida_spawn_list_size(spawns))
	for i := 0; i < n; i++ {
		fs := C.frida_spawn_list_get(spawns, C.int(i))
		s, _ := NewSpawn(fs)
		log.WithFields(logrus.Fields{
			"identifier": s.Identifier,
			"pid":        s.Pid,
		}).Debug("Device: enumerate spawn")
		sl = append(sl, s)
	}
	return
}

func (d *Device) EnumeratePendingChildrenSync() (cl []*Child, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	children := C.frida_device_enumerate_pending_children_sync(d.ptr, cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	}
	if IsNullCPointer(unsafe.Pointer(children)) {
		err = NewErrorAndLog("Device: enumerate pending children error")
		return
	}

	defer func() {
		C.frida_unref(C.gpointer(children))
		children = nil
	}()

	n := int(C.frida_child_list_size(children))
	for i := 0; i < n; i++ {
		fc := C.frida_child_list_get(children, C.int(i))
		c, _ := NewChild(fc)
		log.WithFields(logrus.Fields{
			"identifier": c.Identifier,
			"pid":        c.Pid,
			"ppid":       c.ParentPid,
		}).Debug("Device: enumerate pending children")
		cl = append(cl, c)
	}
	return
}

func (d *Device) fromFridaDevice() (err error) {
	d.Name = C.GoString(C.frida_device_get_name(d.ptr))
	d.ID = C.GoString(C.frida_device_get_id(d.ptr))
	d.Type = uint(C.frida_device_get_dtype(d.ptr))
	return

}

// todo:
// input
// inject_library_file
// inject_library_blob
// open_channel

func NewDevice(fd *C.FridaDevice) (d *Device, err error) {
	d = &Device{ptr: fd}
	err = d.fromFridaDevice()
	return
}

//export onOutput
func onOutput(device *C.FridaDevice, pid C.guint, fd C.gint, data *C.GBytes, userData C.gpointer) {
	if chOutput != nil {
		o := &Output{
			Pid: uint(pid),
			Fd:  int(fd),
		}
		if !IsNullCPointer(unsafe.Pointer(data)) {
			var dSize C.ulong
			dBuf := C.g_bytes_get_data(data, &dSize)
			o.Data = C.GoBytes(unsafe.Pointer(dBuf), C.int(dSize))
		}
		*chOutput <- o
	}
}
