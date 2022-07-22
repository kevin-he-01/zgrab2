package ike

import (
	"fmt"
	"strings"
)

const MAX_TRANSFORMS = 120
// (Technically maximum is 255), but to avoid triggering signed 8-bit integer overflow bugs resulting in negative size

const DH_INVALID = 0

func parseEncAlg(alg string) []Attribute {
	switch alg {
	case "des":
		return []Attribute{
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_DES_CBC_V1)},
		}
	case "3des":
		return []Attribute{
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
		}
	case "aes128":
		return []Attribute{
			{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
		}
	case "aes256":
		return []Attribute{
			{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
		}
	case "camellia128":
		return []Attribute{
			{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_CAMELLIA_CBC_V1)},
		}
	case "camellia192":
		return []Attribute{
			{Type: KEY_LENGTH_V1, Value: uint16ToBytes(192)},
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_CAMELLIA_CBC_V1)},
		}
	case "camellia256":
		return []Attribute{
			{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_CAMELLIA_CBC_V1)},
		}
	// TODO: add camellia support
	default:
		return nil
	}
}

func parseHashAlg(alg string) []Attribute {
	switch alg {
	case "md5":
		return []Attribute{
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(MD5_V1)},
		}
	case "sha1":
		return []Attribute{
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
		}
	case "sha256":
		return []Attribute{
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
		}
	case "sha384":
		return []Attribute{
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_384_V1)},
		}
	case "sha512":
		return []Attribute{
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1)},
		}
	default:
		return nil
	}
}

func parseAuthMethods(method string) []Attribute {
	switch method {
	case "psk":
		return []Attribute{
			{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
		}
	case "dss_sig":
		return []Attribute{
			{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(DSS_SIGNATURES_V1)},
		}
	case "rsa_sig":
		return []Attribute{
			{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
		}
	default:
		return nil
	}
}

func groupNum(group string) uint16 {
	switch group {
	case "modp768":
		return DH_768_V1
	case "modp1024":
		return DH_1024_V1
	case "ec2ngp155":
		return DH_EC2N_GP_155_V1
	case "ec2ngp185":
		return DH_EC2N_GP_185_V1
	case "modp1536":
		return DH_1536_V1
	case "modp2048":
		return DH_2048_V1
	case "modp1024s160":
		return DH_1024_S160_V1
	case "modp2048s224":
		return DH_2048_S224_V1
	case "modp2048s256":
		return DH_2048_S256_V1
	case "modp3072":
		return DH_3072_V1
	case "modp4096":
		return DH_4096_V1
	case "modp6144":
		return DH_6144_V1
	case "modp8192":
		return DH_8192_V1
	default:
		return DH_INVALID
	}
}

func parseGroup(group string) []Attribute {
	num := groupNum(group)
	if num == DH_INVALID {
		return nil
	}
	return []Attribute{
		{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(num)},
	}
}

func ParseTransforms(flags *Flags) (transforms []Transform, err error) {
	if flags.BuiltIn != "ALL" {
		return
	}
	transforms = []Transform{}
	encs := [][]Attribute{}
	hashes := [][]Attribute{}
	authMethods := [][]Attribute{}
	groups := [][]Attribute{}
	for _, encDesc := range strings.Split(flags.ProposeEncAlgs, ",") {
		alg := parseEncAlg(encDesc)
		if alg == nil {
			err = fmt.Errorf("--ike-enc: Unknown encryption scheme %s", encDesc);
			return
		}
		encs = append(encs, alg)
	}
	for _, hashDesc := range strings.Split(flags.ProposeHashAlgs, ",") {
		hash := parseHashAlg(hashDesc)
		if hash == nil {
			err = fmt.Errorf("--ike-hash: Unknown hash %s", hashDesc);
			return
		}
		hashes = append(hashes, hash)
	}
	for _, authMethod := range strings.Split(flags.ProposeAuthMethods, ",") {
		authMeth := parseAuthMethods(authMethod)
		if authMeth == nil {
			err = fmt.Errorf("--ike-auth: Unknown authentication method %s", authMethod);
			return
		}
		authMethods = append(authMethods, authMeth)
	}
	groupStrs := strings.Split(flags.ProposeGroups, ",")
	if (flags.ModeV1 == "aggressive" && flags.Version == 1) {
		if (len(groupStrs) != 1) {
			err = fmt.Errorf("Must propose exactly one group in IKEv1 aggressive mode, got %d", len(groupStrs))
			return
		}
		flags.DHGroup = groupNum(groupStrs[0]) // Override DHGroup
	}
	for _, groupDesc := range groupStrs {
		group := parseGroup(groupDesc)
		if group == nil {
			err = fmt.Errorf("--ike-group: Unknown group %s", groupDesc)
			return
		}
		groups = append(groups, group)
	}
	for _, enc := range encs {
		for _, hash := range hashes {
			for _, am := range authMethods {
				for _, group := range groups {
					attributes := []Attribute{}
					attributes = append(attributes, enc...)
					attributes = append(attributes, hash...)
					attributes = append(attributes, am...)
					attributes = append(attributes, group...)
					transforms = append(transforms, Transform{
						IdV1: KEY_IKE_V1,
						Attributes: attributes,
					})
				}
			}
		}
	}
	if len(transforms) > MAX_TRANSFORMS {
		err = fmt.Errorf("Too many proposed transforms for built-in ALL: MAX is %d, got %d", MAX_TRANSFORMS, len(transforms))
		return
	}
	return
}