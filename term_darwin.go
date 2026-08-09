package main

import "syscall"

const (
	ioctlTermiosGet = syscall.TIOCGETA
	ioctlTermiosSet = syscall.TIOCSETA
)
