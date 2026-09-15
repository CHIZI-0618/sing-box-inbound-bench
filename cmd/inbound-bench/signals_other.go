//go:build !linux && !android && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !solaris

package main

import "os"

func benchmarkSignals() []os.Signal { return []os.Signal{os.Interrupt} }
