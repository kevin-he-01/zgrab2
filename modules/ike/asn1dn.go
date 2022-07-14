package ike

import "encoding/asn1"

//////// Begin ASN.1 DER DN

type CountryName struct {
	OID asn1.ObjectIdentifier
	Country string
}

func MakeCountryName(name string) ([]CountryName) {
	return []CountryName{{OID: []int{2,5,4,6}, Country: name}}
}

type CommonName struct {
	OID asn1.ObjectIdentifier
	Content string
}

func MakeCommonName(content string) ([]CommonName) {
	return []CommonName{{OID: []int{2,5,4,3}, Content: content}}
}

type DistinguishedName struct {
	C []CountryName `asn1:"set,omitempty"`
	CN []CommonName `asn1:"set,omitempty"`
}

//////// End ASN.1 DER DN

func ParseASN1DN() []byte {
	encoding, err := asn1.Marshal(DistinguishedName{C: MakeCountryName("US"), CN: MakeCommonName("abc.example.com")})
	if err != nil {
		panic(err)
	}
	return encoding
}
