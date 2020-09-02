package fridago

/*
 #include "frida-core.h"
*/
import "C"

type SpawnOptions struct {
	ptr  *C.FridaSpawnOptions
	Argv []string
	Envp []string
	Env  []string
	Cwd  string
	// Stdio *Stdio
	// Aux   map[string]interface{}
}

// todo:
// set/get_argv
// set/get_envp
// set/get_env
// set/get_cwd
// set/get_stdio
// get_aux

type Spawn struct {
	ptr        *C.FridaSpawn
	Identifier string
	Pid        uint
}

func (s *Spawn) fromFridaSpawn() (err error) {
	s.Identifier = C.GoString(C.frida_spawn_get_identifier(s.ptr))
	s.Pid = uint(C.frida_spawn_get_pid(s.ptr))
	return

}

func NewSpawn(fs *C.FridaSpawn) (s *Spawn, err error) {
	s = &Spawn{ptr: fs}
	err = s.fromFridaSpawn()
	return
}

//export onSpawnAdded
func onSpawnAdded(dev *C.FridaDevice, ptr *C.FridaSpawn, userData C.gpointer) {
	log.Infof("Device: On spawn added")
	if chSpawnAdd != nil {
		if s, err := NewSpawn(ptr); err == nil {
			*chSpawnAdd <- s
		}
	}
}
