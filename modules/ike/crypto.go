package ike

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"fmt"
	"hash"
)

const MAX_ITER = 10 // FIXME: Should be 256 for correctness, but can be slow. More optimized solution exist (require implementing custom io.Reader)

type prfPlusStream struct {
	buffer []byte
	curr int
}

func prfPlus(key []byte, data []byte, h func() hash.Hash, length int) *prfPlusStream {
	var tPrev []byte
	var buffer []byte
	for i := 1; len(buffer) < length; i++ {
		prf := hmac.New(h, key)
		tPrev = append(tPrev, data...)
		tPrev = append(tPrev, byte(i))
		prf.Write(tPrev)
		tPrev = prf.Sum(nil)
		buffer = append(buffer, tPrev...)
	}
	return &prfPlusStream{
		buffer: buffer,
		curr: 0,
	}
}

func (s *prfPlusStream) genBytes(nr int) []byte {
	next := s.curr + nr
	data := s.buffer[s.curr:next]
	s.curr = next
	return data
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

	keyStream := prfPlus(skeyseed, nonces, prfFunc, prfLength + 2 * (integLength + encLength + prfLength))
	crypto.SK_d  = keyStream.genBytes(prfLength)
	crypto.SK_ai = keyStream.genBytes(integLength)
	crypto.SK_ar = keyStream.genBytes(integLength)
	crypto.SK_ei = keyStream.genBytes(encLength)
	crypto.SK_er = keyStream.genBytes(encLength)
	crypto.SK_pi = keyStream.genBytes(prfLength)
	crypto.SK_pr = keyStream.genBytes(prfLength)
}

// https://datatracker.ietf.org/doc/html/rfc7296#section-2.15
func (c *InitiatorConfig) getSignedOctets(idr *payloadIdentification) (signedOctets []byte) {
	// ResponderSignedOctets = RealMessage2 | NonceIData | MACedIDForR
	signedOctets = append(signedOctets, c.ConnLog.ResponderSAInit.Raw...) // RealMessage2
	signedOctets = append(signedOctets, c.NonceData...)                   // NonceIData
	restOfRespIDPayload := idr.marshal()
	// MACedIDForR = prf(SK_pr, restOfRespIDPayload)
	prf := hmac.New(c.prfFunc, c.ConnLog.Crypto.SK_pr)
	prf.Write(restOfRespIDPayload)
	signedOctets = prf.Sum(signedOctets)
	return
}

func (c *InitiatorConfig) getCiphertextLength(plaintextLength int) int {
	return plaintextLength - plaintextLength%c.blockSize + c.blockSize
}

func ikePad(pt []byte, bs int) []byte {
	// IKE specific padding scheme
	length := len(pt)
	padLength := bs - 1 - length%bs
	padding := make([]byte, padLength)
	pt = append(pt, padding...)
	pt = append(pt, byte(padLength))
	return pt
}

func ikeUnpad(padded []byte) (err error, unpadded []byte) {
	if len(padded) == 0 {
		err = fmt.Errorf("Padded message has zero length")
		return
	}
	padLength := padded[len(padded)-1]
	if int(padLength) >= len(padded) {
		err = fmt.Errorf("Padding length is not strictly less than message length")
		return
	}
	unpadded = padded[:len(padded)-1-int(padLength)]
	return
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

func aesCbcDecrypt(key []byte, iv []byte, ciphertext []byte) (error, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	paddedPt := make([]byte, len(ciphertext))
	mode.CryptBlocks(paddedPt, ciphertext)
	return ikeUnpad(paddedPt)
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

func (c *InitiatorConfig) decrypt(enc []byte) (err error, pt []byte) {
	if len(enc) < c.encIVLength+c.integChecksumLength {
		err = fmt.Errorf("Malformed encrypted payload. Message too short to fit just IV + checksum")
		return
	}
	iv := enc[:c.encIVLength]
	ctxt := enc[c.encIVLength : len(enc)-c.integChecksumLength]
	if len(ctxt)%c.blockSize != 0 {
		err = fmt.Errorf("Ciphertext is not a multiple of block size")
		return
	}
	// Don't check integrity checksum since security isn't important for scanning
	err, pt = aesCbcDecrypt(c.ConnLog.Crypto.SK_er, iv, ctxt)
	return
}
