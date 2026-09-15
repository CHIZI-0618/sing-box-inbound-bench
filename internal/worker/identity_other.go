//go:build !linux && !android

package worker

import "errors"

func prepareUID(requested *uint32) (uint32, error) {
	if requested != nil {
		return 0, errors.New("worker UID selection is only supported on Linux and Android")
	}
	return 0, nil
}
