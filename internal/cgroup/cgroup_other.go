//go:build !linux && !android

package cgroup

import "errors"

func Join(string, int) error {
	return errors.New("cgroup workers are only supported on Linux and Android")
}

func ContainsPID(string, int) (bool, error) {
	return false, errors.New("cgroup workers are only supported on Linux and Android")
}
