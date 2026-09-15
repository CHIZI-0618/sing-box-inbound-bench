package netdev

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// HasListeningSocket checks the kernel socket tables without connecting to a
// transparent listener. A readiness connection would itself be intercepted and
// can create a self-proxy loop for redirect and TPROXY inbounds.
func HasListeningSocket(network string, port uint16, ipv6 bool) (bool, error) {
	path := "/proc/net/" + network
	if ipv6 {
		path += "6"
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	wantState := "0A"
	if network == "udp" {
		wantState = "07"
	} else if network != "tcp" {
		return false, fmt.Errorf("unsupported socket network %q", network)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != wantState {
			continue
		}
		_, rawPort, found := strings.Cut(fields[1], ":")
		if !found {
			continue
		}
		parsed, parseErr := strconv.ParseUint(rawPort, 16, 16)
		if parseErr == nil && uint16(parsed) == port {
			return true, nil
		}
	}
	return false, scanner.Err()
}
