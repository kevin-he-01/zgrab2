package ike

import (
	"fmt"
	"net"
	"strings"
)

func ParseIdentity(identity string) (idType uint8, idData []byte, err error) {
	// Inspired by https://docs.strongswan.org/docs/5.9/config/identityParsing.html
	colon := strings.Index(identity, ":")
	if colon == -1 {
		err = fmt.Errorf("Cannot find colon (:) in identity %s", identity)
		return
	}
	format := identity[:colon]
	content := identity[colon+1:]
	switch format {
	case "email":
		idType = ID_USER_FQDN_V1
		idData = []byte(content)
	case "ipv4":
		idType = ID_IPV4_ADDR_V1
		idData = net.ParseIP(content)
		if idData == nil {
			err = fmt.Errorf("Invalid IP address %s", content)
			return
		}
		idData = net.IP(idData).To4()
		if idData == nil {
			err = fmt.Errorf("Not an IPv4 address %s", content)
			return
		}
	default:
		err = fmt.Errorf("Unrecognized identity format %s", format)
	}
	return
}
