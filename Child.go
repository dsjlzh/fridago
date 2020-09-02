package fridago

/*
 #include "frida-core.h"
*/
import "C"

type Child struct {
	ptr         *C.FridaChild
	Identifier  string
	Pid         uint
	ParentPid   uint
	Path        string
	Argv        []string
	Envp        []string
	ChildOrigin string
}

func (c *Child) setChildOrigin() {
	switch orig := uint(C.frida_child_get_origin(c.ptr)); orig {
	case C.FRIDA_CHILD_ORIGIN_FORK:
		c.ChildOrigin = "fork"
	case C.FRIDA_CHILD_ORIGIN_EXEC:
		c.ChildOrigin = "exec"
	case C.FRIDA_CHILD_ORIGIN_SPAWN:
		c.ChildOrigin = "spawn"
	}
}

func (c *Child) fromFridaChild() (err error) {
	c.Identifier = C.GoString(C.frida_child_get_identifier(c.ptr))
	c.Pid = uint(C.frida_child_get_pid(c.ptr))
	c.ParentPid = uint(C.frida_child_get_parent_pid(c.ptr))
	c.Path = C.GoString(C.frida_child_get_path(c.ptr))
	c.setChildOrigin()

	var argv_length, envp_length C.gint
	argv := C.frida_child_get_argv(c.ptr, &argv_length)
	envp := C.frida_child_get_envp(c.ptr, &envp_length)
	if strs, ok := GStringsToGoStrings(argv, argv_length); ok {
		c.Argv = strs
	}
	if strs, ok := GStringsToGoStrings(envp, envp_length); ok {
		c.Envp = strs
	}
	return
}

func NewChild(fc *C.FridaChild) (c *Child, err error) {
	c = &Child{ptr: fc}
	err = c.fromFridaChild()
	return
}

//export onChildAdded
func onChildAdded(dev *C.FridaDevice, ptr *C.FridaChild, userData C.gpointer) {
	log.Info("Device: On child added")
	if chChildAdd != nil {
		if child, err := NewChild(ptr); err == nil {
			*chChildAdd <- child
		}
	}
}
