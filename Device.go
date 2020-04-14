package fridago

/*
 #include "frida-core.h"
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

type Device struct {
	ptr  *C.FridaDevice
	Name string
	ID   string
	Type uint
}

func (d *Device) PidOf(target string) (pid uint, err error) {
	pl, err := d.EnumerateProcessesSync(target)
	if err != nil {
		return
	}

	if len(pl) > 0 {
		pid = pl[0].Pid
	} else {
		err = NewErrorAndLog("Device, target not found")
	}
	return
}

func (d *Device) AttachPid(pid uint) (s *Session, err error) {
	var gerr *C.GError
	cancel := C.g_cancellable_new()
	sess := C.frida_device_attach_sync(d.ptr, C.uint(pid), cancel, &gerr)
	if gerr != nil {
		err = NewErrorFromGError(gerr)
	} else {
		s = &Session{
			ptr: sess,
			Dev: d,
			Pid: uint(C.frida_session_get_pid(sess)),
		}
	}
	return
}

func (d *Device) Attach(target string) (s *Session, err error) {
	pid, err := d.PidOf(target)
	if err != nil {
		return
	}
	log.WithFields(logrus.Fields{
		"name": target,
		"pid":  pid,
	}).Info("Device: attach process")
	return d.AttachPid(pid)
}

func (d *Device) Spawn(program string) (pid uint, err error) {
	var gerr *C.GError
	opts := C.frida_spawn_options_new()
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

func (d *Device) EnumerateProcessesSync(targetFilter ...string) (pl []*Process, err error) {
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

	hasFilter := len(targetFilter) > 0
	n := int(C.frida_process_list_size(processes))
	for i := 0; i < n; i++ {
		proc := C.frida_process_list_get(processes, C.int(i))
		p := &Process{
			ptr:  proc,
			Name: C.GoString(C.frida_process_get_name(proc)),
			Pid:  uint(C.frida_process_get_pid(proc)),
		}
		log.WithFields(logrus.Fields{
			"name": p.Name,
			"pid":  p.Pid,
		}).Debug("found process")
		if hasFilter {
			if p.Name == targetFilter[0] && p.Pid != 0 {
				pl = append(pl, p)
				return
			}
			continue
		}
		pl = append(pl, p)
	}
	return
}

func (d *Device) FindProcessByPidSync(pid uint) (p *Process, found bool, err error) {
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
	p = &Process{
		ptr:  proc,
		Name: C.GoString(C.frida_process_get_name(proc)),
		Pid:  pid,
	}
	found = true
	return
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
		app := C.frida_application_list_get(applications, C.int(i))
		a := &Application{
			ptr:        app,
			Name:       C.GoString(C.frida_application_get_name(app)),
			Identifier: C.GoString(C.frida_application_get_identifier(app)),
			Pid:        uint(C.frida_application_get_pid(app)),
		}
		log.WithFields(logrus.Fields{
			"name": a.Name,
			"iden": a.Identifier,
			"pid":  a.Pid,
		}).Debug("found application")
		al = append(al, a)
	}
	return
}
