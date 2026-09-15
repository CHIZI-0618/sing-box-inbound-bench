//go:build linux || android

package cgroup

import "testing"

func TestValidatePath(t *testing.T) {
	for _, path := range []string{"/", "/sys/fs/cgroup", "/sys/fs/cgroup/../other", "/tmp/bench"} {
		if err := validatePath(path); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
	if err := validatePath("/sys/fs/cgroup/inbound-bench-run"); err != nil {
		t.Fatal(err)
	}
}
