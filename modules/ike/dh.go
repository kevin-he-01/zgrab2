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
	// https://datatracker.ietf.org/doc/html/rfc2409#section-6.1
	primeMap = map[int]*big.Int {
		1024: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"),
		2048: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"),
	}
	deadbeef = big.NewInt(0xdeadbeef)
	// Currently only stores the default exponent to use for each group, may change in future
	groupSupport = map[uint16]*big.Int{
		//DH_768_V1: new(big.Int).Lsh(deadbeef, 768),
		DH_1024_V1: new(big.Int).Lsh(deadbeef, 1024),
		DH_2048_V1: new(big.Int).Lsh(deadbeef, 2048),
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
	case DH_2048_V1:
		c.dhModP(responderKex, 2048)
	default:
		return fmt.Errorf("computeSecret(): Received unsupported DH group %d", c.DHGroup)
	}
	return nil
}

// User should check isGroupSupported first, this function may panic if group is not supported
func (c *InitiatorConfig) setDHGroup(dhGroup uint16) {
	c.ConnLog.Crypto.DHExponential = groupSupport[dhGroup]
	c.DHGroup = dhGroup
}

func init() {
	for group := range groupSupport {
		supportedGroupList = append(supportedGroupList, group)
	}
}
