package fridago

/*
 #include "frida-core.h"
*/
import "C"

type Process struct {
	ptr  *C.FridaProcess
	Name string
	Pid  uint
}
