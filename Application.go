package fridago

/*
 #include "frida-core.h"
*/
import "C"

type Application struct {
	ptr        *C.FridaApplication
	Identifier string
	Name       string
	Pid        uint
	// SmallIcon *Icon
	// LargeIcon *Icon
}

// todo:
// get_small_icon
// get_large_icon

func (a *Application) fromFridaApplication() (err error) {
	a.Name = C.GoString(C.frida_application_get_name(a.ptr))
	a.Identifier = C.GoString(C.frida_application_get_identifier(a.ptr))
	a.Pid = uint(C.frida_application_get_pid(a.ptr))
	return

}

func NewApplication(fa *C.FridaApplication) (a *Application, err error) {
	a = &Application{ptr: fa}
	err = a.fromFridaApplication()
	return
}
