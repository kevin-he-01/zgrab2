package ike

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"hash"
	"io"
)

const MAX_ITER = 10; // FIXME: Should be 256 for correctness, but can be slow. More optimized solution exist (require implementing custom io.Reader)

func prfPlus(key []byte, data []byte, h func() hash.Hash) io.Reader {
	var tPrev []byte
	var buffer []byte
	for i := 1; i < MAX_ITER; i++ {
		prf := hmac.New(h, key)
		tPrev = append(tPrev, data...)
		tPrev = append(tPrev, byte(i))
		prf.Write(tPrev)
		tPrev = prf.Sum(nil)
		buffer = append(buffer, tPrev...)
	}
	return bytes.NewReader(buffer)
}

func genBytes(rdr io.Reader, nr int) (data []byte) {
	data = make([]byte, nr)
	n, err := rdr.Read(data)
	if n < nr {
		panic(fmt.Errorf("Expect %d bytes, got only %d", nr, n))
	}
	if err != nil {
		panic(err)
	}
	return
}

func (c *InitiatorConfig) computeCryptoKeys(conn *Conn) {
	// FIXME: for now, assume SHA1 as both integrity and PRF, and AES-256 as encryption algo should lookup from config
	prfFunc := sha1.New
	prfLength := 20 // Preferred key length of PRF
	integLength := 20 // Length of integrity algorithm key (for AUTH_NONE like in GCM, it is 0)
	encLength := 32 // Length of key in chosen encryption algorithm
	// *** End crypto selection

	crypto := c.ConnLog.Crypto
	spii := conn.initiatorSPI[:]
	spir := conn.responderSPI[:]
	ni := c.NonceData
	nr := c.responderNonce

	var nonces []byte
	nonces = append(nonces, ni...)
	nonces = append(nonces, nr...)

	prf := hmac.New(prfFunc, nonces)
	prf.Write(crypto.DHSharedSecret)
	skeyseed := prf.Sum(nil)
	crypto.SKEYSEED = skeyseed

	nonces = append(nonces, spii...)
	nonces = append(nonces, spir...)

	keyStream := prfPlus(skeyseed, nonces, prfFunc)
	crypto.SK_d = genBytes(keyStream, prfLength)
	crypto.SK_ai = genBytes(keyStream, integLength)
	crypto.SK_ar = genBytes(keyStream, integLength)
	crypto.SK_ei = genBytes(keyStream, encLength)
	crypto.SK_er = genBytes(keyStream, encLength)
	crypto.SK_pi = genBytes(keyStream, prfLength)
	crypto.SK_pr = genBytes(keyStream, prfLength)
}
