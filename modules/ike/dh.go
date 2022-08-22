package ike

import (
	"fmt"
	"math/big"
)

func hexInt(s string) (bi *big.Int) {
	bi, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("Parsing failed")
	}
	return
}

var (
	primeMap = map[int]*big.Int {
		1024: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"),
	}
	groupSupport = map[uint16]bool{
		DH_1024_V1: true,
	}
	supportedGroupList []uint16
)

// size is in bits
func (c *InitiatorConfig) dhModP(responderKex []byte, size int) {
	gr := new(big.Int).SetBytes(responderKex)
	p := primeMap[size]
	secretInt := gr.Exp(gr, c.ConnLog.Crypto.DHExponential, p)
	c.ConnLog.Crypto.DHSharedSecret = secretInt.FillBytes(make([]byte, size / 8))
}

func isGroupSupported(group uint16) bool {
	_, ok := groupSupport[group]
	return ok
}

func (c *InitiatorConfig) computeSharedSecret(responderKex []byte) (err error) {
	// !!!!! Remember to update groupSupport to include all supported cases!
	switch c.DHGroup {
	case DH_1024_V1:
		c.dhModP(responderKex, 1024)
	default:
		return fmt.Errorf("computeSecret(): Received unsupported DH group %d", c.DHGroup)
	}
	return nil
}

func init() {
	for group := range groupSupport {
		supportedGroupList = append(supportedGroupList, group)
	}
}
