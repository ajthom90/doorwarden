//go:build unix

package main

import (
	"os"
	"syscall"
)

// dbOwner returns the owner uid of path and whether it differs from the
// effective uid (replaced in tests).
var dbOwner = func(path string) (int, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), int(st.Uid) != os.Geteuid()
}
