package ike

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
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
	prfFunc := c.prfFunc
	prfLength := c.prfKeyLength
	integLength := c.integKeyLength
	encLength := c.encKeyLength

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

func (c *InitiatorConfig) getCiphertextLength(plaintextLength int) int {
	return plaintextLength - plaintextLength % c.blockSize + c.blockSize
}

func ikePad(pt []byte, bs int) []byte {
	// IKE specific padding scheme
	length := len(pt)
	padLength := bs - 1 - length % bs
	padding := make([]byte, padLength)
	pt = append(pt, padding...)
	pt = append(pt, byte(padLength))
	return pt
}

func aesCbcEncrypt(key []byte, iv []byte, plaintext []byte, ciphertext []byte) {
	plaintext = ikePad(plaintext, len(iv)) // block size must be same as IV length
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
}

func (c *InitiatorConfig) encryptAndDigest(iv []byte, associatedData []byte, plaintext []byte, ciphertext []byte) []byte {
	crypto := c.ConnLog.Crypto
	// fmt.Printf("IV: %s\n", hex.EncodeToString(iv))
	// fmt.Printf("Associated data: %s\n", hex.EncodeToString(associatedData))
	// fmt.Printf("Plaintext: %s\n", hex.EncodeToString(plaintext))
	// copy(ciphertext, bytes.Repeat([]byte{0xcc}, c.getCiphertextLength(len(plaintext)))) // round up to block size
	aesCbcEncrypt(crypto.SK_ei, iv, plaintext, ciphertext)
	// return bytes.Repeat([]byte{0x55}, c.integChecksumLength)
	
	// Integrity tag
	// Need to MAC associatedData + iv + ciphertext in non GCM mode
	prf := hmac.New(c.integFunc, crypto.SK_ai)
	prf.Write(associatedData)
	prf.Write(iv)
	prf.Write(ciphertext)
	return prf.Sum(nil)[:c.integChecksumLength]
}
