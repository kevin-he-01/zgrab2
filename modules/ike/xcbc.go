package ike

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

var oneAES = bytes.Repeat([]byte{0x01}, aes.BlockSize)
var twoAES = bytes.Repeat([]byte{0x02}, aes.BlockSize)
var threeAES = bytes.Repeat([]byte{0x03}, aes.BlockSize)

func xorInPlace(a []byte, b []byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}

func padXor(plaintext []byte, k2 []byte, k3 []byte) (result []byte) {
	result = append(result, plaintext...)
	if len(plaintext) % aes.BlockSize == 0 && len(plaintext) != 0 {
		xorInPlace(result[len(result) - aes.BlockSize:], k2)
	} else {
		result = append(result, 0x80) // 1000_0000
		padBytes := aes.BlockSize - 1 - len(plaintext) % aes.BlockSize
		for i := 0; i < padBytes; i++ {
			result = append(result, 0x00)
		}
		xorInPlace(result[len(result) - aes.BlockSize:], k3)
	}
	return
}

// https://www.rfc-editor.org/rfc/rfc3566#section-4
// Append MAC output to `data` and return `data`
func aes128XCBCMac(data []byte, key []byte, plaintext []byte) []byte {
	kBlock, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	k1 := make([]byte, aes.BlockSize)
	k2 := make([]byte, aes.BlockSize)
	k3 := make([]byte, aes.BlockSize)
	kBlock.Encrypt(k1, oneAES)
	kBlock.Encrypt(k2, twoAES)
	kBlock.Encrypt(k3, threeAES)
	block, err := aes.NewCipher(k1)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize))
	buffer := padXor(plaintext, k2, k3)
	mode.CryptBlocks(buffer, buffer)
	// Copy slice to avoid memory leak (buffer can be significantly larger than digest)
	data = append(data, buffer[len(buffer)-aes.BlockSize:]...)
	return data
}

// https://www.rfc-editor.org/rfc/rfc4434.html#section-2
// Append PRF output to `data` and return `data`
func aes128XCBCPrf(data []byte, key []byte, plaintext []byte) []byte {
	if len(key) == 16 {
		data = aes128XCBCMac(data, key, plaintext)
	} else if len(key) < 16 {
		var lengthenedKey []byte
		lengthenedKey = append(lengthenedKey, key...)
		for len(lengthenedKey) < 16 {
			lengthenedKey = append(lengthenedKey, 0x00)
		}
		data = aes128XCBCMac(data, lengthenedKey, plaintext)
	} else {
		key = aes128XCBCMac(nil, make([]byte, 16), key)
		data = aes128XCBCMac(data, key, plaintext)
	}
	return data
}
