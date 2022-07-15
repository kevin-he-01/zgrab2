package ike

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

//////// Begin ASN.1 DER DN

// Useful guide
// https://www.vito.io/2020/10/18/ans1-field-ordering

type StringAttribute struct {
	Type asn1.ObjectIdentifier
	Value string
}

type AnySET []interface{}

//////// End ASN.1 DER DN

func OIDFromAttribute(attributeName string) asn1.ObjectIdentifier {
	// See https://www.ibm.com/docs/en/ibm-mq/7.5?topic=certificates-distinguished-names
	// for an exhaustive list
	switch attributeName {
	case "C": // countryName
		return []int{2,5,4,6}
	case "ST": // State or Province Name
		return []int{2,5,4,8}
	case "L": // localityName
		return []int{2,5,4,7}
	case "O": // organizationName
		return []int{2,5,4,10}
	case "OU": // Organizational Unit Name
		return []int{2,5,4,11}
	case "CN": // commonName
		return []int{2,5,4,3}
	default:
		return nil
	}
}

func ParseASN1DN(attrs string) ([]byte, error) {
	// encoding, err := asn1.Marshal(DistinguishedName{C: MakeCountryName("US"), CN: MakeCommonName(cn)}) // Must match EXACTLY, even the addition of a single host will fail
	// encoding, err := asn1.Marshal(DistinguishedName{C: MakeCountryName("US"), CN: MakeCommonName(cn)})
	attributes := []AnySET{}
	for _, attr := range strings.Split(attrs, ",") {
		attr = strings.Trim(attr, " ")
		oid := OIDFromAttribute(attr)
		if oid == nil {
			return nil, fmt.Errorf("Invalid DN attribute '%s'", attr)
		}
		attributes = append(attributes, []interface{}{StringAttribute{Type: oid, Value: "*"}}) // Fow now use all wildcards
	}
	encoding, err := asn1.Marshal(attributes)
	if err != nil {
		panic(err)
	}
	return encoding, nil
}
