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
	// Also in: https://datatracker.ietf.org/doc/html/rfc7296#appendix-B
	// Additional groups in https://datatracker.ietf.org/doc/html/rfc3526
	// Simply copy paste and remove space with
	// python3 -c 'import sys; print(sys.stdin.read().replace(" ", "").replace("\n", ""))'
	primeMap = map[int]*big.Int {
		768: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"),
		1024: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"),
		1536: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"),
		2048: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"),
		3072: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"),
		4096: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF"),
	}
	deadbeef = big.NewInt(0xdeadbeef)
	// Currently only stores the default exponent to use for each group, may change in future
	bigIntOne = big.NewInt(1)
	groupSupport = map[uint16]*big.Int{
		DH_768_V2: new(big.Int).Lsh(deadbeef, 768),
		DH_1024_V2: new(big.Int).Lsh(deadbeef, 1024),
		DH_1536_V2: new(big.Int).Lsh(deadbeef, 1536),
		DH_2048_V2: new(big.Int).Lsh(deadbeef, 2048),
		DH_3072_V2: new(big.Int).Lsh(deadbeef, 3072),
		DH_4096_V2: new(big.Int).Lsh(deadbeef, 4096),
		DH_256_ECP_V2: bigIntOne,
		DH_384_ECP_V2: bigIntOne,
		DH_521_ECP_V2: bigIntOne,
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
	case DH_768_V2:
		c.dhModP(responderKex, 768)
	case DH_1024_V2:
		c.dhModP(responderKex, 1024)
	case DH_1536_V2:
		c.dhModP(responderKex, 1536)
	case DH_2048_V2:
		c.dhModP(responderKex, 2048)
	case DH_3072_V2:
		c.dhModP(responderKex, 3072)
	case DH_4096_V2:
		c.dhModP(responderKex, 4096)
	case DH_256_ECP_V2, DH_384_ECP_V2, DH_521_ECP_V2:
		if len(responderKex) % 2 != 0 {
			return fmt.Errorf("computeSharedSecret(): Length of responder kex value for ECDH is not even")
		}
		// https://www.rfc-editor.org/rfc/rfc5903.html#section-7
		// The Diffie-Hellman shared secret value consists of the x value of the
		// Diffie-Hellman common value.
		c.ConnLog.Crypto.DHSharedSecret = responderKex[:len(responderKex)/2] // exponent 1, so just the identity function
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
