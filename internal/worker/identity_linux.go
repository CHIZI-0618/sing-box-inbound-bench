//go:build linux || android

package worker

import (
	"fmt"
	"os"
	"syscall"
)

func prepareUID(requested *uint32) (uint32, error) {
	current := uint32(os.Geteuid())
	if requested == nil || *requested == current {
		return current, nil
	}
	if err := syscall.Setuid(int(*requested)); err != nil {
		return current, fmt.Errorf("set worker UID to %d: %w", *requested, err)
	}
	current = uint32(os.Geteuid())
	if current != *requested {
		return current, fmt.Errorf("worker UID is %d after requesting %d", current, *requested)
	}
	return current, nil
}
