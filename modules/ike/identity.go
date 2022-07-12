package ike

import (
	"fmt"
	"net"
	"strings"
)

const FLAG = "--ike-identity"

func ParseIPv4(content string) (idData []byte, err error) {
	idData = net.ParseIP(content)
	if idData == nil {
		err = fmt.Errorf(FLAG + ": Invalid IP address %s", content)
		return
	}
	idData = net.IP(idData).To4()
	if idData == nil {
		err = fmt.Errorf(FLAG + ": Not an IPv4 address %s", content)
		return
	}
	return
}

func ParseIPv4Subnet(content string) (idData []byte, err error) {
	_, ipNet, cidrErr := net.ParseCIDR(content)
	if cidrErr != nil {
		err = fmt.Errorf(FLAG + ": Invalid CIDR address %s", content)
		return
	}
	ipAddr := ipNet.IP
	subnet := ipNet.Mask
	if len(ipAddr) != 4 || len(subnet) != 4 {
		err = fmt.Errorf(FLAG + ": Not an IPv4 address %s", content)
		return
	}
	idData = append(ipAddr, subnet...)
	return
}

func ParseIdentity(identity string) (idType uint8, idData []byte, err error) {
	// Inspired by https://docs.strongswan.org/docs/5.9/config/identityParsing.html
	// See https://datatracker.ietf.org/doc/html/rfc2407#section-4.6.2.1 for format
	colon := strings.Index(identity, ":")
	if colon == -1 {
		err = fmt.Errorf(FLAG + ": Cannot find colon (:) in identity %s", identity)
		return
	}
	format := identity[:colon]
	content := identity[colon+1:]
	switch format {
	case "email":
		idType = ID_USER_FQDN_V1
		idData = []byte(content)
	case "fqdn":
		idType = ID_FQDN_V1
		idData = []byte(content)
	case "ipv4":
		idType = ID_IPV4_ADDR_V1
		idData, err = ParseIPv4(content)
		if err != nil {
			return
		}
	case "ipv4range":
		// Technically illegal in identity payloads according to RFC
		// But just used to see if real implementations accept them
		// erroneously
		dashPos := strings.Index(content, "-")
		if dashPos != -1 {
			// Range
			idType = ID_IPV4_ADDR_RANGE_V1
			start, errStart := ParseIPv4(content[:dashPos])
			if errStart != nil {
				err = errStart
				return
			}
			end, errEnd := ParseIPv4(content[dashPos+1:])
			if errEnd != nil {
				err = errEnd
				return
			}
			idData = append(start, end...)
		} else {
			// Subnet mask (in CIDR notation expected)
			idType = ID_IPV4_ADDR_SUBNET_V1
			idData, err = ParseIPv4Subnet(content)
			if err != nil {
				return
			}
		}
	default:
		err = fmt.Errorf(FLAG + ": Unrecognized identity format %s", format)
	}
	return
}
