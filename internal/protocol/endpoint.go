package protocol

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

const EncodedEndpointSize = 20

func EncodeEndpoint(address net.Addr) ([]byte, error) {
	endpoint, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return nil, err
	}
	endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap().WithZone(""), endpoint.Port())
	encoded := make([]byte, EncodedEndpointSize)
	if endpoint.Addr().Is4() {
		encoded[0] = 4
		address4 := endpoint.Addr().As4()
		copy(encoded[14:18], address4[:])
	} else if endpoint.Addr().Is6() {
		encoded[0] = 6
		address16 := endpoint.Addr().As16()
		copy(encoded[2:18], address16[:])
	} else {
		return nil, errors.New("unsupported endpoint address family")
	}
	binary.BigEndian.PutUint16(encoded[18:20], endpoint.Port())
	return encoded, nil
}

func DecodeEndpoint(encoded []byte) (string, error) {
	if len(encoded) != EncodedEndpointSize {
		return "", errors.New("invalid encoded endpoint length")
	}
	var address netip.Addr
	switch encoded[0] {
	case 4:
		var address4 [4]byte
		copy(address4[:], encoded[14:18])
		address = netip.AddrFrom4(address4)
	case 6:
		var address16 [16]byte
		copy(address16[:], encoded[2:18])
		address = netip.AddrFrom16(address16)
	default:
		return "", errors.New("invalid encoded endpoint family")
	}
	return netip.AddrPortFrom(address, binary.BigEndian.Uint16(encoded[18:20])).String(), nil
}

func CanonicalEndpoint(value string) (string, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil {
		return "", err
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap().WithZone(""), endpoint.Port()).String(), nil
}
