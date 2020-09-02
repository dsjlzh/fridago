package fridago

/*
 #include "frida-core.h"
*/
import "C"

type Crash struct {
	ptr         *C.FridaCrash
	Pid         uint
	ProcessName string
	Summary     string
	Report      string
	parameters  []byte
}
