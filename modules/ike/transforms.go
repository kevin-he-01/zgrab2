package ike

import (
	"fmt"
	"strings"
)

const MAX_TRANSFORMS = 120
// (Technically maximum is 255), but to avoid triggering signed 8-bit integer overflow bugs resulting in negative size

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
	// TODO: add SHA-3 support
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


func parseGroup(group string) []Attribute {
	switch group {
	case "modp768":
		return []Attribute{
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1)},
		}
	case "modp1024":
		return []Attribute{
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
		}
	case "modp2048":
		return []Attribute{
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
		}
	case "ec2ngp155":
		return []Attribute{
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_EC2N_GP_155_V1)},
		}
	case "ec2ngp185":
		return []Attribute{
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_EC2N_GP_185_V1)},
		}
	default:
		return nil
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
		}
		encs = append(encs, alg)
	}
	for _, hashDesc := range strings.Split(flags.ProposeHashAlgs, ",") {
		hash := parseHashAlg(hashDesc)
		if hash == nil {
			err = fmt.Errorf("--ike-hash: Unknown hash %s", hashDesc);
		}
		hashes = append(hashes, hash)
	}
	for _, authMethod := range strings.Split(flags.ProposeAuthMethods, ",") {
		authMeth := parseAuthMethods(authMethod)
		if authMeth == nil {
			err = fmt.Errorf("--ike-hash: Unknown authentication method %s", authMethod);
		}
		authMethods = append(authMethods, authMeth)
	}
	for _, groupDesc := range strings.Split(flags.ProposeGroups, ",") {
		group := parseGroup(groupDesc)
		if group == nil {
			err = fmt.Errorf("--ike-group: Unknown group %s", groupDesc);
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