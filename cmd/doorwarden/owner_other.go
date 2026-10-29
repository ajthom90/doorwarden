//go:build !unix

package main

// dbOwner: file ownership is not checked on this platform.
var dbOwner = func(string) (int, bool) { return 0, false }
