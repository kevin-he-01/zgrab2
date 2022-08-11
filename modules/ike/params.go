package ike

import (
	"encoding/hex"
	"fmt"
)

// Per RFC 7296: IKEv2 nonce DATA must be between 16 to 256 bytes long, inclusive
// Source: https://datatracker.ietf.org/doc/html/rfc7296#section-3.9
// > The size of the Nonce Data MUST be between 16 and 256 octets,
// > inclusive.  Nonce values MUST NOT be reused.
// Per RFC 2409: IKEv1 nonce PAYLOAD (DATA + 4 bytes) must be between 8 and 256 bytes long
// Source: https://datatracker.ietf.org/doc/html/rfc2409#section-5
// > The length of nonce payload MUST be between 8 and 256 bytes
// > inclusive.
// Pick the intersection of the two requirements: data of size 16 to 252 bytes long, inclusive
const (
	MIN_NONCE_LENGTH = 16
	MAX_NONCE_LENGTH = 252
)

func ParseNonce(nonce string) (data []byte, err error) {
	data, err = hex.DecodeString(nonce)
	if err != nil {
		return
	}
	if len(data) < MIN_NONCE_LENGTH || len(data) > MAX_NONCE_LENGTH {
		err = fmt.Errorf("Nonce length must be between %d and %d bytes long, inclusive, got nonce of length %d",
			MIN_NONCE_LENGTH, MAX_NONCE_LENGTH, len(data))
	}
	return
}
