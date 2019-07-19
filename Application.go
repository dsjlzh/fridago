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
}
