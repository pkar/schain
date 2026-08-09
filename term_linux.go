package main

import "syscall"

const (
	ioctlTermiosGet = syscall.TCGETS
	ioctlTermiosSet = syscall.TCSETS
)
