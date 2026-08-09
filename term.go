//go:build darwin || linux

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

func ioctlTermios(fd uintptr, req uintptr, t *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(t)))
	if errno != 0 {
		return errno
	}
	return nil
}

// readSecret prompts on the controlling terminal and reads a line with
// echo disabled. Falls back to plain stdin when no tty is available
// (e.g. piped input in scripts or tests).
func readSecret(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprint(os.Stderr, prompt)
		return readLine(os.Stdin)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)

	var old syscall.Termios
	if err := ioctlTermios(tty.Fd(), ioctlTermiosGet, &old); err != nil {
		return nil, err
	}
	noecho := old
	noecho.Lflag &^= syscall.ECHO
	if err := ioctlTermios(tty.Fd(), ioctlTermiosSet, &noecho); err != nil {
		return nil, err
	}
	line, rerr := readLine(tty)
	ioctlTermios(tty.Fd(), ioctlTermiosSet, &old)
	fmt.Fprintln(tty)
	return line, rerr
}

func readLine(r io.Reader) ([]byte, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			if buf[0] != '\r' {
				line = append(line, buf[0])
			}
			continue
		}
		if err == io.EOF {
			if len(line) > 0 {
				break
			}
			return nil, io.ErrUnexpectedEOF
		}
		if err != nil {
			return nil, err
		}
	}
	return line, nil
}

// confirm asks a yes/no question on the terminal (or stdin fallback).
func confirm(prompt string) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	var in io.Reader
	var out io.Writer
	if err != nil {
		in, out = os.Stdin, os.Stderr
	} else {
		defer tty.Close()
		in, out = tty, tty
	}
	fmt.Fprintf(out, "%s [y/N] ", prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return line == "y\n" || line == "Y\n" || line == "yes\n"
}
