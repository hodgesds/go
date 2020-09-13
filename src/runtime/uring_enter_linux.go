package runtime

import (
	"syscall"
)

// Enter is used to submit to the queue.
func Enter(fd int, toSubmit uint, minComplete uint, flags uint) (int, error) {
	res, _, errno := syscall.Syscall6(
		EnterSyscall,
		uintptr(fd),
		uintptr(toSubmit),
		uintptr(minComplete),
		uintptr(flags),
		// uintptr(unsafe.Pointer(sigset)), *unix.Sigset_t
		uintptr(0),
		uintptr(0),
	)
	if errno != 0 {
		var err error
		err = errno
		return 0, err
	}
	if res < 0 {
		return 0, syscall.Errno(-res)
	}

	return int(res), nil
}
