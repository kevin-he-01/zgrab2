package ike

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	zlog "github.com/sirupsen/logrus" // mock zlog
)

const (
	MID_IKE_SA_INIT = 0
	MID_IKE_AUTH    = 1
)

var (
	allDhGroupTransforms = []Transform{
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_768_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1536_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_3072_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_4096_V2},
		// {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_6144_V2}, // Will make UDP payload too big causing crashes
		// {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_8192_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_S160_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S224_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S256_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_192_ECP_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_224_ECP_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_384_ECP_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_521_ECP_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_224_BRAINPOOL_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_384_BRAINPOOL_V2},
		{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_512_BRAINPOOL_V2},
	}
	allIntegrityTransforms = []Transform{
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_DES_MAC_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_KPDK_MD5_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_AES_XCBC_96_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_128_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_160_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_AES_CMAC_96_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_AES_128_GMAC_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_AES_192_GMAC_V2},
		{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_AES_256_GMAC_V2},
	}
	allPrfTransforms = []Transform{
		{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_AES128_CMAC_V2},
		{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
		{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
		{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
		{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_AES128_XCBC_V2},
		{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_TIGER_V2},
		{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
		{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
	}
	allEncTransforms = []Transform{
		{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
		{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
		{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
		// {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CTR_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
		// {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CTR_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
		// {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CTR_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
		// {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_CAMELLIA_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
		// {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_CAMELLIA_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
		// {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_CAMELLIA_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
		// {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_CAMELLIA_CTR_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
		// {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_CAMELLIA_CTR_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
		// {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_CAMELLIA_CTR_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
		// {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_DES_V2},
		{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
	}
	allAuthEncTransforms = []Transform{ // Authenticated encryption
		{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
		{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
		{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
	}
	allEsnTransforms = []Transform{ // ESN (Extended Sequence Numbers) are needed for ESP
		{Type: EXTENDED_SEQUENCE_NUMBERS_V2, Id: NO_EXTENDED_SEQUENCE_NUMBERS_V2},
		{Type: EXTENDED_SEQUENCE_NUMBERS_V2, Id: YES_EXTENDED_SEQUENCE_NUMBERS_V2},
	}
)

// Initiator implements an IKE initiator.
type Initiator struct {
	*Conn
}

func NewInitiator(c *Conn) *Initiator {
	return &Initiator{c}
}

// NewInitiatorConn establishes an IKE connection using c as the underlying
// transport.
func NewInitiatorConn(c net.Conn, _ string, config *InitiatorConfig) (*Conn, error) {
	fullConf := *config
	fullConf.SetDefaults()                       // set defaults for general Config
	if err := fullConf.SetConfig(); err != nil { // expand built-in configs
		return nil, fmt.Errorf("ike: bad config: %v", err)
	}

	conn := &Conn{conn: c, probeFile: config.ProbeFile}

	if err := conn.initiatorHandshake(&fullConf); err != nil {
		// c.Close() // will be handled outside in `defer` clause
		return nil, err
	}

	return conn, nil
}

// Dial initiates a connection to the given IKE responder.
func Dial(network, addr string, config *InitiatorConfig) (*Initiator, error) {
	conn, err := net.DialTimeout(network, addr, config.Timeout)
	if err != nil {
		return nil, err
	}

	if config.Timeout != 0 {
		conn.SetDeadline(time.Now().Add(config.Timeout))
	}

	c, err := NewInitiatorConn(conn, addr, config)
	if err != nil {
		return nil, err
	}

	return NewInitiator(c), nil
}

type InitiatorConfig struct {
	// Config contains configuration that is shared between IKE initiators and responders.
	Config

	// IKE Version (1 or 2)
	Version uint16 `json:"version"`

	// IKEv1 Mode ("aggressive" or "main")
	ModeV1 string `json:"exchange_type,omitempty"`

	// Diffie-Hellman group to send in the initiator key exchange message
	DHGroup uint16 `json:"dh_group"`

	// Diffie-Hellman key exchange value to send in the initiator key exchange message (must match DHGroup).
	KexValues [][]byte `json:"kex_value,omitempty"`

	// List of proposals to send in the initiator security association message.
	Proposals []Proposal `json:"proposals"`

	// List of proposals to send in the initiator's second security association message.
	ESPProposals []Proposal `json:"esp_proposals"`

	// Timeout is the maximum amount of time for the UDP connection to
	// establish.  A Timeout of zero means no timeout.
	Timeout time.Duration

	// BuiltIn specifies a built-in configuration that may overwrite other command-line options.
	BuiltIn string

	IdentityType uint8

	IdentityData []byte

	NonceData []byte

	// Used in ALL built-in
	AllTransforms []Transform

	ProbeFile string

	NoFragment bool

	// Used in EAP
	RestrictDHGroup bool
	BetterHashes bool

	// Certificate request
	CertReq []byte

	// Extra cipher suite selection
	EnableAESXCBCPrf bool

	//// Misc connection states

	// data received from the most recent N(COOKIE) payload.
	// See https://datatracker.ietf.org/doc/html/rfc7296#section-2.6
	cookie []byte

	// Responder nonce and key exchange
	responderNonce []byte
	responderKex   []byte

	// Crypto parameters (depends on responder selected proposal)
	blockCipher         blockCipherCtor
	prfFunc             hashCtor
	xcbcPrf             bool // Whether AES-128-XCBC_PRF (RFC 4434) is used
	prfKeyLength        int // Preferred key length of selected PRF
	integFunc           hashCtor
	integKeyLength      int // Key length for the selected integrity algorithm (0 for AUTH_NONE)
	integChecksumLength int // Length of checksum in encrypted payload
	encKeyLength        int // Length of key in chosen encryption algorithm
	encIVLength         int // Length of IV in encrypted payload
	blockSize           int // block size (always same as IV length???), allow pre-calculation of payload length

	// Flag to indicate everything is initialized (avoid nil pointer deference)
	saInitComplete bool

	// Fragments for IKE_AUTH received
	numFragsReceived     uint16
	fragmentsReceived    [][]byte
	firstFragmentMessage *ikeMessage
}

func (c *Conn) initiatorHandshake(config *InitiatorConfig) (err error) {

	if _, err = config.Rand.Read(c.initiatorSPI[:]); err != nil {
		return errors.New("ike: unable to read from random")
	}

	if config.Version == VersionIKEv2 {
		if config.BuiltIn == "EAP" {
			return c.initiatorHandshakeV2EAP(config)
		} else {
			return c.initiatorHandshakeV2(config)
		}
	}
	if config.Version == VersionIKEv1 {
		if config.ModeV1 == "main" {
			return c.initiatorHandshakeMain(config)
		}
		if config.ModeV1 == "aggressive" {
			return c.initiatorHandshakeAggressive(config)
		}
	}
	return errors.New("ike: invalid initiator config")
}

func (c *Conn) initiatorHandshakeMain(config *InitiatorConfig) (err error) {
	// Send IKEv1 Main Mode SA message
	msg := c.buildInitiatorMainSA(config)
	if err = c.writeMessage(msg); err != nil {
		return
	}
	config.ConnLog.InitiatorMainSA = msg.MakeLog()

	var response *ikeMessage

	// Messages can come in any order and be retransmitted, so expect anything
	for config.ConnLog.ResponderMainSA == nil {

		// Read response
		response, err = c.readMessage()
		if err != nil {
			return
		}
		log := response.MakeLog()

		// Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
		if err = response.containsErrorNotification(); err != nil {
			config.ConnLog.ErrorNotification = response.MakeLog()
			return
		}

		// Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
		if !bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid initiator SPI")
			continue
		}
		if !bytes.Equal(c.responderSPI[:], make([]byte, 8)) && !bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid responder SPI")
			continue
		}

		if response.containsPayload(SECURITY_ASSOCIATION_V1) {
			if config.ConnLog.ResponderMainSA == nil {
				config.ConnLog.ResponderMainSA = log
				copy(c.responderSPI[:], response.hdr.responderSPI[:])
				config.DHGroup = response.getResponderDHGroup()
				if config.DHGroup == 0 {
					err = errors.New("Unable to extract Diffie-Hellman group from responser Security Exchange")
					return
				}

				if _, ok := groupKexMap[config.DHGroup]; !ok {
					err = errors.New("Unsupported Diffie-Hellman group in responder Security Association")
					return
				}

			} else if bytes.Equal(log.Raw, config.ConnLog.ResponderMainSA.Raw) {
				// ignore retransmissions
			} else {
				// they sent two different SA messages back, which is unexpected
				config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			}
			continue
		}

		if response.containsPayload(KEY_EXCHANGE_V1) && response.containsPayload(NONCE_V1) {
			log := response.MakeLog()
			if config.ConnLog.ResponderMainKE == nil {
				// They sent a KE message before we did. Does not follow the RFC, but OK.
				config.ConnLog.ResponderMainKE = log
			} else if bytes.Equal(log.Raw, config.ConnLog.ResponderMainKE.Raw) {
				// ignore retransmissions
			} else {
				// they sent two different KE messages back, which is unexpected
				config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			}
			continue
		}

		// unexpected message
		config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
	}

	// Build IKEv1 Main Mode KE message
	msg = c.buildInitiatorMainKE(config)
	if err = c.writeMessage(msg); err != nil {
		return
	}
	config.ConnLog.InitiatorMainKE = msg.MakeLog()

	// Messages can come in any order and be retransmitted, so expect anything
	for config.ConnLog.ResponderMainKE == nil {

		// Read response
		response, err = c.readMessage()
		if err != nil {
			return
		}
		log := response.MakeLog()

		// Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
		if err = response.containsErrorNotification(); err != nil {
			config.ConnLog.ErrorNotification = response.MakeLog()
			return
		}

		// Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
		if !bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid initiator SPI")
			continue
		}
		if !bytes.Equal(c.responderSPI[:], make([]byte, 8)) && !bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid responder SPI")
			continue
		}

		if response.containsPayload(SECURITY_ASSOCIATION_V1) {
			if config.ConnLog.ResponderMainSA == nil {
				zlog.Fatalf("execution error: config.ConnLog.ResponderMainSA should not be nil")
			} else if bytes.Equal(log.Raw, config.ConnLog.ResponderMainSA.Raw) {
				// ignore retransmissions
			} else {
				// they sent two different SA messages back, which is unexpected
				config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			}
			continue
		}

		if response.containsPayload(KEY_EXCHANGE_V1) && response.containsPayload(NONCE_V1) {
			if config.ConnLog.ResponderMainKE == nil {
				// They sent a KE message before we did. Does not follow the RFC, but OK.
				config.ConnLog.ResponderMainKE = log
			} else if bytes.Equal(log.Raw, config.ConnLog.ResponderMainKE.Raw) {
				// ignore retransmissions
			} else {
				// they sent two different KE messages back, which is unexpected
				config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			}
			continue
		}
		// unexpected message
		config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
	}

	// TODO: HASH_I and HASH_R messages
	return
}

func (c *Conn) buildInitiatorMainSA(config *InitiatorConfig) (msg *ikeMessage) {
	msg = new(ikeMessage)
	msg.hdr = new(ikeHeader)
	copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
	// msg.hdr.responderSPI
	msg.hdr.nextPayload = SECURITY_ASSOCIATION_V1
	msg.hdr.majorVersion = VersionIKEv1
	msg.hdr.minorVersion = 0
	msg.hdr.exchangeType = IDENTITY_PROTECTION_V1
	msg.hdr.flags = 0
	msg.hdr.messageId = MID_IKE_SA_INIT // Message ID
	msg.hdr.length = IKE_HEADER_LEN     // header + body

	// add payloads
	payload1 := c.buildPayload(config, SECURITY_ASSOCIATION_V1)
	payload1.nextPayload = NO_NEXT_PAYLOAD
	msg.hdr.length += uint32(payload1.length)
	msg.payloads = append(msg.payloads, payload1)

	return
}

func (c *Conn) buildInitiatorMainKE(config *InitiatorConfig) (msg *ikeMessage) {
	msg = new(ikeMessage)
	msg.hdr = new(ikeHeader)
	if config.ConnLog.InitiatorMainSA == nil || config.ConnLog.ResponderMainSA == nil {
		return
	}
	copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
	copy(msg.hdr.responderSPI[:], c.responderSPI[:])
	msg.hdr.nextPayload = KEY_EXCHANGE_V1
	msg.hdr.majorVersion = VersionIKEv1
	msg.hdr.minorVersion = 0
	msg.hdr.exchangeType = IDENTITY_PROTECTION_V1
	msg.hdr.flags = 0
	msg.hdr.messageId = 0           // Message ID
	msg.hdr.length = IKE_HEADER_LEN // header + body

	// add payloads
	payload1 := c.buildPayload(config, KEY_EXCHANGE_V1)
	payload1.nextPayload = NONCE_V1
	msg.hdr.length += uint32(payload1.length)
	msg.payloads = append(msg.payloads, payload1)

	payload2 := c.buildPayload(config, NONCE_V1)
	payload2.nextPayload = NO_NEXT_PAYLOAD
	msg.hdr.length += uint32(payload2.length)
	msg.payloads = append(msg.payloads, payload2)

	return
}

func (c *Conn) initiatorHandshakeAggressive(config *InitiatorConfig) (err error) {

	// Send IKEv1 Aggressive Mode message
	msg := c.buildInitiatorAggressive(config)
	if err = c.writeMessage(msg); err != nil {
		return
	}
	config.ConnLog.InitiatorAggressive = msg.MakeLog()

	var response *ikeMessage

	// Messages can come in any order and be retransmitted, so expect anything
	for config.ConnLog.ResponderAggressive == nil {

		// Read response
		response, err = c.readMessage()
		if err != nil {
			return
		}
		log := response.MakeLog()

		// Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
		if err = response.containsErrorNotification(); err != nil {
			config.ConnLog.ErrorNotification = response.MakeLog()
			return
		}

		// Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
		if !bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid initiator SPI")
			continue
		}
		if !bytes.Equal(c.responderSPI[:], make([]byte, 8)) && !bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid responder SPI")
			continue
		}

		if response.containsPayload(SECURITY_ASSOCIATION_V1) && response.containsPayload(KEY_EXCHANGE_V1) {
			config.ConnLog.ResponderAggressive = log
			continue
		}

		// unexpected message
		config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
	}
	return
}

func (c *Conn) buildInitiatorAggressive(config *InitiatorConfig) (msg *ikeMessage) {
	msg = new(ikeMessage)
	msg.hdr = new(ikeHeader)
	copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
	// msg.hdr.responderSPI
	msg.hdr.nextPayload = SECURITY_ASSOCIATION_V1
	msg.hdr.majorVersion = VersionIKEv1
	msg.hdr.minorVersion = 0
	msg.hdr.exchangeType = AGGRESSIVE_V1
	msg.hdr.flags = 0
	msg.hdr.messageId = 0           // Message ID
	msg.hdr.length = IKE_HEADER_LEN // header + body

	// add payloads
	payload1 := c.buildPayload(config, SECURITY_ASSOCIATION_V1)
	payload1.nextPayload = KEY_EXCHANGE_V1
	msg.hdr.length += uint32(payload1.length)
	msg.payloads = append(msg.payloads, payload1)

	payload2 := c.buildPayload(config, KEY_EXCHANGE_V1)
	payload2.nextPayload = NONCE_V1
	msg.hdr.length += uint32(payload2.length)
	msg.payloads = append(msg.payloads, payload2)

	payload3 := c.buildPayload(config, NONCE_V1)
	payload3.nextPayload = IDENTIFICATION_V1
	msg.hdr.length += uint32(payload3.length)
	msg.payloads = append(msg.payloads, payload3)

	payload4 := c.buildPayload(config, IDENTIFICATION_V1)
	payload4.nextPayload = NO_NEXT_PAYLOAD
	msg.hdr.length += uint32(payload4.length)
	msg.payloads = append(msg.payloads, payload4)

	if config.CertReq != nil {
		crPayload := c.buildPayload(config, CERTIFICATE_REQUEST_V1)
		msg.payloads = append(msg.payloads, crPayload)
	}

	return
}

func (c *Conn) initiatorHandshakeV2(config *InitiatorConfig) (err error) {

	// Send IKE_SA_INIT
	msg := c.buildInitiatorSAInit(config)
	if err = c.writeMessage(msg); err != nil {
		return
	}
	config.ConnLog.InitiatorSAInit = msg.MakeLog()

	var response *ikeMessage

	// Messages can come in any order and be retransmitted, so expect anything
	for config.ConnLog.ResponderSAInit == nil {

		// Read response
		response, err = c.readMessage()
		if err != nil {
			return
		}
		log := response.MakeLog()

		// Check if response contains an INVALID_KE_PAYLOAD request. If so, initiate another handshake with the requested group.
		if dhGroup := response.containsInvalidKEPayload(); dhGroup != 0 {
			config.DHGroup = dhGroup

			if _, ok := groupKexMap[config.DHGroup]; !ok {
				err = fmt.Errorf("Unsupported Diffie-Hellman group %d requested on INVALID_KE_PAYLOAD", config.DHGroup)
				return
			}

			return c.initiatorHandshakeV2(config)
		}

		// Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
		if err = response.containsErrorNotification(); err != nil {
			config.ConnLog.ErrorNotification = response.MakeLog()
			return
		}

		// Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
		if !bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid initiator SPI")
			continue
		}
		if !bytes.Equal(c.responderSPI[:], make([]byte, 8)) && !bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid responder SPI")
			continue
		}

		if response.containsPayload(SECURITY_ASSOCIATION_V2) && response.containsPayload(KEY_EXCHANGE_V2) {
			config.ConnLog.ResponderSAInit = log
			continue
		}

		// unexpected message
		config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
	}
	return
}

func guessResponseOrigin(r *ikeMessage) string {
	switch r.hdr.messageId {
	case MID_IKE_SA_INIT:
		return "responder_ike_sa_init"
	case MID_IKE_AUTH:
		return "responder_ike_auth"
	default:
		return "unknown"
	}
}

func (c *Conn) initiatorHandshakeV2EAP(config *InitiatorConfig) (err error) {

	// Send IKE_SA_INIT
	msg := c.buildInitiatorSAInit(config)
	if err = c.writeMessage(msg); err != nil {
		return
	}
	config.ConnLog.InitiatorSAInit = msg.MakeLog()

	var response *ikeMessage

	// Messages can come in any order and be retransmitted, so expect anything
	for config.ConnLog.ResponderSAInit == nil || config.ConnLog.ResponderAuth == nil {

		// Read response
		response, err = c.readMessage()
		if err != nil {
			if err == msgParseErr {
				// response.raw
				config.ConnLog.UnparsableRaw = response.raw
			}
			return
		}
		origin := guessResponseOrigin(response)
		log := response.MakeLog()

		if bytes.Equal(response.raw, config.ConnLog.InitiatorSAInit.Raw) {
			err = ErrEchoServer
			return
		}

		if cookie := response.containsCookie(); cookie != nil {
			zlog.Debug("N(COOKIE) received. Retrying with cookie")
			config.cookie = cookie
			return c.initiatorHandshakeV2EAP(config)
		}

		// Check if response contains an INVALID_KE_PAYLOAD request. If so, initiate another handshake with the requested group.
		if dhGroup := response.containsInvalidKEPayload(); dhGroup != 0 {
			zlog.Debugf("config.DHGroup = %d guess is wrong, host requested %d instead", config.DHGroup, dhGroup)
			if !isGroupSupported(dhGroup) {
				// Should not happen for hosts adhering to RFC
				err = fmt.Errorf("Responder chooses a group (%d) not requested in SAi in INVALID_KE_PAYLOAD", dhGroup)
				return
			}
			config.setDHGroup(dhGroup)

			if _, ok := groupKexMap[config.DHGroup]; !ok {
				err = fmt.Errorf("Unsupported Diffie-Hellman group %d requested on INVALID_KE_PAYLOAD", config.DHGroup)
				return
			}

			return c.initiatorHandshakeV2EAP(config)
		}

		// Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
		if err = response.containsErrorNotification(); err != nil {
			config.ConnLog.ErrorOrigin = origin
			config.ConnLog.ErrorNotification = log
			return
		}

		// Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
		if !bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid initiator SPI")
			continue
		}

		if bytes.Equal(c.responderSPI[:], make([]byte, 8)) {
			copy(c.responderSPI[:], response.hdr.responderSPI[:])
			if response.hdr.messageId != MID_IKE_SA_INIT {
				err = fmt.Errorf("First Message ID must be IKE_SA_INIT (0), but got %d", response.hdr.messageId)
				return
			}
		}

		if !bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid responder SPI")
			continue
		}

		switch response.hdr.messageId {
		case MID_IKE_SA_INIT:
			if config.saInitComplete {
				config.ConnLog.Retransmit = append(config.ConnLog.Retransmit, log)
				continue
			}
			config.ConnLog.ResponderSAInit = log
			err = response.setCryptoParamsV2(config)
			if err != nil {
				return
			}
			err = config.computeSharedSecret(config.responderKex)
			if err != nil {
				return
			}
			err = config.computeCryptoKeys(c)
			if err != nil {
				return
			}
			config.saInitComplete = true

			// Send IKE_AUTH
			msg := c.buildInitiatorAuth(config)
			config.ConnLog.InitiatorAuth = msg.MakeLog()
			msg.encrypt(config)
			config.ConnLog.InitiatorAuthEncrypted = msg.MakeLog()
			if err = c.writeMessage(msg); err != nil {
				return
			}
		case MID_IKE_AUTH:
			if !config.saInitComplete {
				// crypto parameters are uninitialized at this point, so fail
				config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
				err = fmt.Errorf("Received IKE_AUTH packet before IKE_SA_INIT")
			}
			var decMsg *ikeMessage
			decMsg, err = response.processResponderAuth(log, config)
			if err != nil {
				return
			}
			if decMsg != nil {
				if err = decMsg.containsErrorNotification(); err != nil {
					config.ConnLog.ErrorOrigin = origin
					config.ConnLog.ErrorNotification = decMsg.MakeLog()
					return
				}
				config.ConnLog.ResponderAuth = decMsg.MakeLog()
				idr := decMsg.getResponderIdPayload()
				if idr == nil {
					err = fmt.Errorf("Cannot find IDr payload in IKE_AUTH")
					return
				}
				config.ConnLog.Crypto.ResponderSignedOctets = config.getSignedOctets(idr)
			}
		default:
			// unexpected message
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
		}
	}
	return
}

func (c *Conn) buildInitiatorSAInit(config *InitiatorConfig) (msg *ikeMessage) {
	msg = new(ikeMessage)
	msg.hdr = new(ikeHeader)
	copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
	// msg.hdr.responderSPI
	// msg.hdr.nextPayload = SECURITY_ASSOCIATION_V2
	msg.hdr.majorVersion = VersionIKEv2
	msg.hdr.minorVersion = 0
	msg.hdr.exchangeType = IKE_SA_INIT_V2
	msg.hdr.flags = 0x08                // flags (bit 3 set)
	msg.hdr.messageId = MID_IKE_SA_INIT // Message ID
	// msg.hdr.length = IKE_HEADER_LEN // header + body

	// add payloads

	if config.cookie != nil {
		cookiePayload := buildNotifyCookie(config.cookie)
		msg.payloads = append(msg.payloads, cookiePayload)
	}

	payload1 := c.buildPayload(config, SECURITY_ASSOCIATION_V2)
	// payload1.nextPayload = KEY_EXCHANGE_V2
	// msg.hdr.length += uint32(payload1.length)
	msg.payloads = append(msg.payloads, payload1)

	payload2 := c.buildPayload(config, KEY_EXCHANGE_V2)
	// payload2.nextPayload = NONCE_V2
	// msg.hdr.length += uint32(payload2.length)
	msg.payloads = append(msg.payloads, payload2)

	payload3 := c.buildPayload(config, NONCE_V2)
	// payload3.nextPayload = NO_NEXT_PAYLOAD
	// msg.hdr.length += uint32(payload3.length)
	msg.payloads = append(msg.payloads, payload3)

	if !config.NoFragment {
		payloadFragmentation := notifyFragmentationV2()
		msg.payloads = append(msg.payloads, payloadFragmentation)
	}

	if config.BetterHashes {
		payloadSignatureHashes := buildNotifySignatureHashFunctions()
		msg.payloads = append(msg.payloads, payloadSignatureHashes)
	}

	return
}

func (c *Conn) buildInitiatorAuth(config *InitiatorConfig) (msg *ikeMessage) {
	msg = new(ikeMessage)
	msg.hdr = new(ikeHeader)
	copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
	copy(msg.hdr.responderSPI[:], c.responderSPI[:])
	msg.hdr.majorVersion = VersionIKEv2
	msg.hdr.minorVersion = 0
	msg.hdr.exchangeType = IKE_AUTH_V2
	msg.hdr.flags = 0x08             // flags (bit 3 set)
	msg.hdr.messageId = MID_IKE_AUTH // Message ID

	payload1 := c.buildPayload(config, IDENTIFICATION_INITIATOR_V2)
	msg.payloads = append(msg.payloads, payload1)

	if config.CertReq != nil {
		crPayload := c.buildPayload(config, CERTIFICATE_REQUEST_V2)
		msg.payloads = append(msg.payloads, crPayload)
	}

	payload2 := new(payload)
	payload2.payloadType = SECURITY_ASSOCIATION_V2
	payload2.body = c.buildPayloadSecurityAssociationV2(config, true)
	msg.payloads = append(msg.payloads, payload2)

	payload3 := c.buildPayload(config, TRAFFIC_SELECTOR_INITIATOR_V2)
	msg.payloads = append(msg.payloads, payload3)

	payload4 := c.buildPayload(config, TRAFFIC_SELECTOR_RESPONDER_V2)
	msg.payloads = append(msg.payloads, payload4)

	return
}

func (c *Conn) buildPayload(config *InitiatorConfig, payloadType uint8) (p *payload) {
	p = new(payload)
	p.payloadType = payloadType

	switch payloadType {
	//  IKEv1
	case SECURITY_ASSOCIATION_V1:
		p.body = c.buildPayloadSecurityAssociationV1(config)
	case KEY_EXCHANGE_V1:
		p.body = c.buildPayloadKeyExchangeV1(config)
	case IDENTIFICATION_V1:
		p.body = c.buildPayloadIdentification(config)
	case CERTIFICATE_V1:
	case CERTIFICATE_REQUEST_V1:
		p.body = c.buildPayloadCertificateRequestV1(config)
	case HASH_V1:
	case SIGNATURE_V1:
	case NONCE_V1:
		p.body = c.buildPayloadNonce(config)
	case NOTIFICATION_V1:
	case DELETE_V1:
	case VENDOR_ID_V1:
		p.body = c.buildPayloadVendorId(config)
	//  IKEv2
	case SECURITY_ASSOCIATION_V2:
		p.body = c.buildPayloadSecurityAssociationV2(config, false) // defaults to IKE
	case KEY_EXCHANGE_V2:
		p.body = c.buildPayloadKeyExchangeV2(config)
	case IDENTIFICATION_INITIATOR_V2:
		p.body = c.buildPayloadIdentification(config)
	case IDENTIFICATION_RESPONDER_V2:
	case CERTIFICATE_V2:
	case CERTIFICATE_REQUEST_V2:
		p.body = c.buildPayloadCertificateRequest(config)
	case AUTHENTICATION_V2:
	case NONCE_V2:
		p.body = c.buildPayloadNonce(config)
	case NOTIFY_V2:
	case DELETE_V2:
	case VENDOR_ID_V2:
		p.body = c.buildPayloadVendorId(config)
	case TRAFFIC_SELECTOR_INITIATOR_V2:
		p.body = c.buildPayloadTrafficSelector(config)
	case TRAFFIC_SELECTOR_RESPONDER_V2:
		p.body = c.buildPayloadTrafficSelector(config)
	case ENCRYPTED_V2:
	case CONFIGURATION_V2:
	case EXTENSIBLE_AUTHENTICATION_V2:
	default:
		zlog.Fatalf("unrecognized payload type: %v", p.payloadType)
	}

	return
}

func notifyFragmentationV2() (p *payload) {
	p = new(payload)
	p.payloadType = NOTIFY_V2

	body := new(payloadNotifyV2)
	// body.protocolId = 0
	// body.spi = nil
	body.notifyType = IKEV2_FRAGMENTATION_SUPPORTED_V2
	// body.notifyData = nil

	p.body = body
	return
}

func buildNotifyCookie(cookie []byte) (p *payload) {
	p = new(payload)
	p.payloadType = NOTIFY_V2

	body := new(payloadNotifyV2)
	// body.protocolId = 0
	// body.spi = nil
	body.notifyType = COOKIE_V2
	body.notifyData = cookie

	p.body = body
	return
}

func buildNotifySignatureHashFunctions() (p *payload) {
	p = new(payload)
	p.payloadType = NOTIFY_V2

	body := new(payloadNotifyV2)
	// body.protocolId = 0
	// body.spi = nil
	body.notifyType = SIGNATURE_HASH_ALGORITHMS_V2
	// https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#hash-algorithms
	body.notifyData = []byte("\x00\x01\x00\x02\x00\x03\x00\x04") // SHA1 and SHA2-256/384/512

	p.body = body
	return
}

func (c *Conn) buildPayloadSecurityAssociationV1(config *InitiatorConfig) (p *payloadSecurityAssociationV1) {
	p = new(payloadSecurityAssociationV1)
	p.doi = IPSEC_V1
	// situation is a bitmask
	sit := SIT_IDENTITY_ONLY_V1
	p.situation = make([]byte, 4)
	p.situation[0] = uint8(sit >> 24)
	p.situation[1] = uint8(sit >> 16)
	p.situation[2] = uint8(sit >> 8)
	p.situation[3] = uint8(sit)
	for _, proposalConfig := range config.Proposals {
		p.proposals = append(p.proposals, buildProposalV1(proposalConfig))
	}
	if len(p.proposals) > 0 {
		p.proposals[len(p.proposals)-1].lastProposal = true
	}
	return p
}

func buildTransformV1(transformConfig Transform) (t *transformV1) {
	t = new(transformV1)
	t.lastTransform = false
	t.transformNum = transformConfig.Num
	t.length = 8
	t.transformId = transformConfig.IdV1
	for _, attributeConfig := range transformConfig.Attributes {
		a := buildAttribute(attributeConfig)
		t.attributes = append(t.attributes, a)
		t.length += uint16(len(a.marshal()))
	}
	return
}

func buildProposalV1(proposalConfig Proposal) (p *proposalV1) {
	p = new(proposalV1)
	p.protocolId = PROTO_ISAKMP_V1
	p.proposalNum = proposalConfig.ProposalNum
	p.lastProposal = false
	p.spi = []byte{}

	for _, transformConfig := range proposalConfig.Transforms {
		t := buildTransformV1(transformConfig)
		p.transforms = append(p.transforms, t)
		p.length += t.length
	}
	return
}

func (c *Conn) buildPayloadSecurityAssociationV2(config *InitiatorConfig, esp bool) (p *payloadSecurityAssociationV2) {
	p = new(payloadSecurityAssociationV2)
	proposals := config.Proposals
	var espSpi []byte
	if esp {
		proposals = config.ESPProposals
		espSpi = config.readRand(4)
	}
	for _, proposalConfig := range proposals {
		p.proposals = append(p.proposals, buildProposalV2(proposalConfig, espSpi))
	}
	if len(p.proposals) > 0 {
		p.proposals[len(p.proposals)-1].lastProposal = true
	}
	return p
}

func buildProposalV2(proposalConfig Proposal, espSpi []byte) (p *proposalV2) {
	p = new(proposalV2)
	if espSpi != nil {
		p.protocolId = ESP_V2
	} else {
		p.protocolId = IKE_V2
	}
	p.proposalNum = proposalConfig.ProposalNum
	p.lastProposal = false
	if espSpi != nil {
		p.spi = espSpi
	} else {
		p.spi = []byte{}
	}

	for _, transformConfig := range proposalConfig.Transforms {
		t := buildTransformV2(transformConfig)
		p.transforms = append(p.transforms, t)
		p.length += t.length
	}
	return
}

func buildTransformV2(transformConfig Transform) (t *transformV2) {
	t = new(transformV2)
	t.lastTransform = false
	t.transformType = transformConfig.Type
	t.length = 8
	t.transformId = transformConfig.Id
	for _, attributeConfig := range transformConfig.Attributes {
		a := buildAttribute(attributeConfig)
		t.attributes = append(t.attributes, a)
		t.length += uint16(len(a.marshal()))
	}
	return
}

func buildAttribute(attributeConfig Attribute) (a *attribute) {
	a = new(attribute)
	a.attributeType = attributeConfig.Type
	a.attributeValue = make([]byte, len(attributeConfig.Value))
	copy(a.attributeValue, attributeConfig.Value)
	return
}

func (c *Conn) buildPayloadKeyExchangeV1(config *InitiatorConfig) (p *payloadKeyExchangeV1) {
	p = new(payloadKeyExchangeV1)
	if len(config.KexValues) > 0 {
		p.keyExchangeData = append(p.keyExchangeData, config.KexValues[0]...)
		return
	}
	// TODO: generate random key here
	if val, ok := groupKexMap[config.DHGroup]; ok {
		p.keyExchangeData = append(p.keyExchangeData, val...)
	} else {
		zlog.Fatalf("unsupported group: %d. conn: %s", config.DHGroup, c)
	}
	return
}

func (c *Conn) buildPayloadKeyExchangeV2(config *InitiatorConfig) (p *payloadKeyExchangeV2) {
	p = new(payloadKeyExchangeV2)
	p.dhGroup = config.DHGroup
	if len(config.KexValues) > 0 {
		p.keyExchangeData = append(p.keyExchangeData, config.KexValues[0]...)
		return
	}
	// TODO: generate random key here
	if val, ok := groupKexMap[config.DHGroup]; ok {
		p.keyExchangeData = append(p.keyExchangeData, val...)
	} else {
		zlog.Fatalf("unsupported group: %d. conn: %s", p.dhGroup, c)
	}
	return
}

func (c *Conn) buildPayloadNonce(config *InitiatorConfig) (p *payloadNonce) {
	p = new(payloadNonce)
	p.nonceData = append(p.nonceData, config.NonceData...)
	return
}

func (c *Conn) buildPayloadIdentification(config *InitiatorConfig) (p *payloadIdentification) {
	// See https://datatracker.ietf.org/doc/html/rfc2407#section-4.6.2.1 for format
	// See https://datatracker.ietf.org/doc/html/rfc4945 for even more details on identity authentication
	p = new(payloadIdentification)
	p.idType = config.IdentityType
	p.idData = config.IdentityData
	return
}

func (c *Conn) buildPayloadCertificateRequest(config *InitiatorConfig) (p *payloadCertificateRequest) {
	p = new(payloadCertificateRequest)
	p.encoding = X509_CERTIFICATE_SIGNATURE_V2
	p.certificateAuth = config.CertReq
	return
}

func (c *Conn) buildPayloadCertificateRequestV1(config *InitiatorConfig) (p *payloadCertificateRequest) {
	p = new(payloadCertificateRequest)
	p.encoding = 0;
	p.certificateAuth = nil
	return
}

func (c *Conn) buildPayloadVendorId(config *InitiatorConfig) (p *payloadVendorId) {
	p = new(payloadVendorId)
	return
}

func (c *Conn) buildPayloadTrafficSelector(config *InitiatorConfig) (p *payloadTrafficSelector) {
	p = new(payloadTrafficSelector)
	return
}

func uint16ToBytes(num uint16) []byte {
	return []byte{uint8(num >> 8), uint8(num)}
}

func uint16FromBytes(by []byte) uint16 {
	if len(by) != 2 {
		panic("Bad length")
	}
	return uint16(by[0]) << 8 + uint16(by[1])
}

func (c *InitiatorConfig) MakeOPENBSD() {
	if c.Version == VersionIKEv1 {
		panic("not implemented")
	} else {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_DES_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_EC2N_GP_155_V1},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_EC2N_GP_185_V1},
			},
			},
		}
	}
}

// Constructing a UDP probe (not expecting a positive response)
func (c *InitiatorConfig) MakeUDP_PROBE() {
	c.DHGroup = DH_1024_V1
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(MD5_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
			}},
		}
	} else {
		panic("not implemented")
	}
}

func (c *InitiatorConfig) MakeBASELINE() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				// AES-CBC-128, SHA1, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_1024_S160, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_S160_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_2048_S224, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_S224_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_2048_S256, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_S256_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_256_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_1024
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// AES-CBC-256, SHA1,  DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_256_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1)},
				},
				},
				// 1-DES, MD5, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(MD5_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// 3-DES, MD5, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(MD5_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// 3-DES, SHA1, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// 3-DES, SHA1, DH_1024, RSA_SIGNATURES
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// AES-CBC-256, SHA2_256,  DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA2_256, DH_2048, RSA_SIGNATURES
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
			}},
		}
	} else {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_S160_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S224_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S256_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2},
			},
			},
			{ProposalNum: 2, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_S160_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S224_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S256_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2},
			},
			},
		}
	}
}

func (c *InitiatorConfig) MakeEAP() {
	if c.Version == VersionIKEv1 {
		panic("EAP not supported for IKEv1")
	} else {
		transforms := []Transform{
			{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
			{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
			{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
			{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
			// {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
			// {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
			// {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
			// {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
			// {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
			// {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2},
			// {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2},
			// {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2},
			// {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
			// {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
			// {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_V2},
			// {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_V2},
			// {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_S160_V2},
			// {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S224_V2},
			// {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S256_V2},
			// {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2},
			// {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2},
		}
		for prf := range prfMap {
			transforms = append(transforms, Transform{Type: PSEUDORANDOM_FUNCTION_V2, Id: prf})
		}
		if c.EnableAESXCBCPrf {
			transforms = append(transforms, Transform{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_AES128_XCBC_V2})
		}
		for integ := range integAlgMap {
			transforms = append(transforms, Transform{Type: INTEGRITY_ALGORITHM_V2, Id: integ})
		}
		if c.RestrictDHGroup {
			// Only propose the initial group if c.RestrictDHGroup is on
			transforms = append(transforms, Transform{Type: DIFFIE_HELLMAN_GROUP_V2, Id: c.DHGroup})
		} else {
			for _, group := range supportedGroupList {
				transforms = append(transforms, Transform{Type: DIFFIE_HELLMAN_GROUP_V2, Id: group})
			}
		}
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: transforms},
		}
		// Combined-mode ciphers include
		// both integrity and encryption in a single encryption algorithm, and
		// MUST either offer no integrity algorithm or a single integrity
		// algorithm of "NONE", with no integrity algorithm being the
		// RECOMMENDED method.
		// https://datatracker.ietf.org/doc/html/rfc7296#section-3.3
		c.ESPProposals = []Proposal{
			{ProposalNum: 1, Transforms: concatTransforms(
				allAuthEncTransforms,
				// []Transform{ // No integrity algorithm is recommended
				// 	{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2},
				// },
				allEsnTransforms,
			)},
			{ProposalNum: 2, Transforms: concatTransforms(
				allEncTransforms,
				allIntegrityTransforms,
				allEsnTransforms,
			)},
		}
	}
}

func (c *InitiatorConfig) GetTransformsFor(authMethod uint16) []Transform {
	dhGroup := c.DHGroup
	return []Transform{
		// AES-CBC-256, SHA2_256, RSA_SIGNATURES
		{IdV1: KEY_IKE_V1, Attributes: []Attribute{
			{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
			{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(authMethod)},
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(dhGroup)},
		},
		},
		// AES-CBC-128, SHA2_256, RSA_SIGNATURES
		{IdV1: KEY_IKE_V1, Attributes: []Attribute{
			{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
			{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(authMethod)},
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(dhGroup)},
		},
		},
		// 3DES, SHA2_256, RSA_SIGNATURES
		{IdV1: KEY_IKE_V1, Attributes: []Attribute{
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
			{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(authMethod)},
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(dhGroup)},
		},
		},
		// AES-CBC-256, SHA1, RSA_SIGNATURES
		{IdV1: KEY_IKE_V1, Attributes: []Attribute{
			{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
			{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(authMethod)},
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(dhGroup)},
		},
		},
		// AES-CBC-128, SHA1, RSA_SIGNATURES
		{IdV1: KEY_IKE_V1, Attributes: []Attribute{
			{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
			{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(authMethod)},
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(dhGroup)},
		},
		},
		// 3DES, SHA1, RSA_SIGNATURES
		{IdV1: KEY_IKE_V1, Attributes: []Attribute{
			{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
			{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
			{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(authMethod)},
			{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(dhGroup)},
		},
		},
	}
}

func concatTransforms(transforms ...[]Transform) []Transform {
	build := []Transform{}
	for _, transform := range transforms {
		build = append(build, transform...)
	}
	return build
}

func (c *InitiatorConfig) MakeALL() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: c.AllTransforms},
		}
	} else {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: concatTransforms(
				allAuthEncTransforms,
				allPrfTransforms,
				[]Transform{
					{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2},
				},
				allDhGroupTransforms,
			)},
			{ProposalNum: 2, Transforms: concatTransforms(
				allEncTransforms,
				allPrfTransforms,
				allIntegrityTransforms,
				allDhGroupTransforms,
			)},
		}
	}
}

// Extract RSA signature from host
func (c *InitiatorConfig) MakeRSA_SIGNATURE() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: c.GetTransformsFor(RSA_SIGNATURES_V1)},
		}
	} else {
		panic("Cannot use RSA_SIGNATURE with IKEv2")
	}
}

func (c *InitiatorConfig) MakePSK() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: c.GetTransformsFor(PRE_SHARED_KEY_V1)},
		}
	} else {
		panic("Cannot use PSK with IKEv2")
	}
}

func (c *InitiatorConfig) MakePSK_OR_RSA() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: append(c.GetTransformsFor(PRE_SHARED_KEY_V1), c.GetTransformsFor(RSA_SIGNATURES_V1)...)},
		}
	} else {
		panic("Cannot use PSK or RSA with IKEv2")
	}
}

func (c *InitiatorConfig) MakeFORTIGATE() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				// Send these ciphersuites first, since the attack is more efficient with smaller groups:

				// 3-DES, SHA1, DH_768, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_768, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1)},
				},
				},
				// 3-DES, SHA1, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},

				// Default ciphersuites:

				// 3-DES, SHA1, DH_1536, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_1536, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},

				// Additional supported ciphersuites:

				// 3-DES, SHA1, DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA2-256, DH_1536, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-256, SHA2-512, DH_1536, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-256, SHA2-256, DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA2-512, DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},

				// Try them all with RSA signatures instead of PSK
				// 3-DES, SHA1, DH_768, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_768, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1)},
				},
				},
				// 3-DES, SHA1, DH_1024, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_1024, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// 3-DES, SHA1, DH_1536, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_1536, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// 3-DES, SHA1, DH_2048, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_2048, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA2-256, DH_1536, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-256, SHA2-512, DH_1536, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-256, SHA2-256, DH_2048, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA2-512, DH_2048, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
			}},
		}
	} else {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_DES_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_768_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1536_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_V2},
			},
			},
		}
	}
}

func (c *InitiatorConfig) MakeECDH_BASELINE() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				// AES-CBC-128, SHA1, DH_224_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_224_ECP_V1)},
				},
				},
				// AES-CBC-224, SHA1, DH_224_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(224)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_224_ECP_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_256_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_256_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_384_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_384_ECP_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_384_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_384_ECP_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_521_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_521_ECP_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_521_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_521_ECP_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_256_BRAINPOOL, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_BRAINPOOL_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_256_BRAINPOOL, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_224_BRAINPOOL_V1)},
				},
				},
			}},
		}
	} else {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_224_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_384_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_521_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2},
			},
			},
			{ProposalNum: 2, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_224_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_384_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_521_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2},
			},
			},
		}
	}
}

func (c *InitiatorConfig) MakeSINGLE_GROUP() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				// AES-CBC-128, SHA1, <group>, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(c.DHGroup)},
				},
				},
				// AES-CBC-256, SHA1, <group>, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(c.DHGroup)},
				},
				},
			}},
		}
	} else {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: c.DHGroup},
			},
			},
			{ProposalNum: 2, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: c.DHGroup},
			},
			},
		}
	}
}

func (c *InitiatorConfig) SetConfig() error {
	// Sanity check the IKE version.
	if !(c.Version == 1 || c.Version == 2) {
		return fmt.Errorf("ike: invalid version: %d", c.Version)
	}

	// V1 and V2 group numbers are the same for the groups that both version support.
	configString := strings.ToUpper(c.BuiltIn)
	switch configString {
	case "": // do not use a built-in config
		if len(c.Proposals) < 1 {
			zlog.Fatalf("No proposals specified: use ike-builtin or ike-proposals to specify a proposal")
		}
	case "UDP_PROBE":
		c.MakeUDP_PROBE()
	case "OPENBSD":
		//c.DHGroup = DH_1024_V1
		//c.DHGroup = DH_EC2N_GP_155_V1
		c.DHGroup = DH_EC2N_GP_185_V1
		c.MakeOPENBSD()
	case "BASELINE":
		c.DHGroup = DH_1024_V1
		c.MakeBASELINE()
	case "EAP":
		c.ConnLog.Crypto = new(CryptoInfo)
		if !isGroupSupported(c.DHGroup) {
			zlog.Fatalf("Unsupported Diffie Hellman group specified in --ike-dh-group")
		}
		c.setDHGroup(c.DHGroup)
		c.MakeEAP()
	case "FORTIGATE":
		c.DHGroup = DH_1536_V1
		c.MakeFORTIGATE()
	case "1024S160":
		c.DHGroup = DH_1024_S160_V1
		c.MakeSINGLE_GROUP()
	case "2048S224":
		c.DHGroup = DH_2048_S224_V1
		c.MakeSINGLE_GROUP()
	case "2048S256":
		c.DHGroup = DH_2048_S256_V1
		c.MakeSINGLE_GROUP()
	// Extract RSA signature from host
	case "RSA_SIGNATURE":
		c.MakeRSA_SIGNATURE()
	// Same as RSA_SIGNATURE except with PSK, used to see what caused those NO_PROPOSAL_CHOSEN messages
	case "PSK":
		c.MakePSK()
	case "PSK_OR_RSA":
		c.MakePSK_OR_RSA()
	// ALL transforms supporting some encryption schemes
	case "ALL":
		c.MakeALL()
	// check for subgroup order validation
	// 1
	case "1024S160_1":
		c.DHGroup = DH_1024_S160_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 128))
		c.KexValues[0][127] = 0x01
	case "2048S224_1":
		c.DHGroup = DH_2048_S224_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 224))
		c.KexValues[0][224] = 0x01
	case "2048S256_1":
		c.DHGroup = DH_2048_S256_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 256))
		c.KexValues[0][255] = 0x01
	// p-1
	case "1024S160_M1":
		c.DHGroup = DH_1024_S160_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_1024_S160_M1)
	case "2048S224_M1":
		c.DHGroup = DH_2048_S224_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_2048_S224_M1)
	case "2048S256_M1":
		c.DHGroup = DH_2048_S256_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_2048_S256_M1)
	// 0
	case "1024S160_0":
		c.DHGroup = DH_1024_S160_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 128))
	case "2048S224_0":
		c.DHGroup = DH_2048_S224_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 224))
	case "2048S256_0":
		c.DHGroup = DH_2048_S256_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 256))
	// subgroup of order 7
	case "1024S160_S7":
		c.DHGroup = DH_1024_S160_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_1024_S160_S7)
	// subgroup of order 3
	case "2048S224_S3":
		c.DHGroup = DH_2048_S224_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_2048_S224_S3)
	// subgroup of order 7
	case "2048S256_S7":
		c.DHGroup = DH_2048_S256_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_2048_S256_S7)

	// elliptic curve configs
	case "ECDH_BASELINE":
		c.DHGroup = DH_256_ECP_V1
		c.MakeECDH_BASELINE()
	case "256_ECP":
		c.DHGroup = DH_256_ECP_V1
		c.MakeSINGLE_GROUP()
	case "256_ECP_INVALID_S5":
		c.DHGroup = DH_256_ECP_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_256_ECP_INVALID_S5)
	case "256_ECP_TWIST_S5":
		c.DHGroup = DH_256_ECP_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_256_ECP_INVALID_S5)
	case "224_ECP":
		c.DHGroup = DH_224_ECP_V1
		c.MakeSINGLE_GROUP()
	case "224_ECP_INVALID_S13":
		c.DHGroup = DH_224_ECP_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_224_ECP_INVALID_S13)
	case "224_ECP_TWIST_S11":
		c.DHGroup = DH_224_ECP_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_224_ECP_TWIST_S11)
	case "384_ECP":
		c.DHGroup = DH_384_ECP_V1
		c.MakeSINGLE_GROUP()
	case "521_ECP":
		c.DHGroup = DH_521_ECP_V1
		c.MakeSINGLE_GROUP()
	case "256_BRAINPOOL":
		c.DHGroup = DH_256_BRAINPOOL_V1
		c.MakeSINGLE_GROUP()
	case "EC2N_155":
		c.DHGroup = DH_EC2N_GP_155_V1
		c.MakeSINGLE_GROUP()
	case "EC2N_185":
		c.DHGroup = DH_EC2N_GP_185_V1
		c.MakeSINGLE_GROUP()
	// Not yet standardized as of Nov. 2016: https://tools.ietf.org/html/draft-ietf-ipsecme-safecurves-05#section-2
	//case "CURVE25519":
	//    c.DHGroup = DH_CURVE25519_V2
	//    c.MakeSINGLE_GROUP()
	default:
		return fmt.Errorf("ike: invalid --ike-builtin value: %s", configString)
	}
	// Sanity-check the config
	if c.DHGroup == 0 {
		return fmt.Errorf("ike: invalid DH group: %d", c.DHGroup)
	}
	if len(c.Proposals) == 0 {
		return fmt.Errorf("ike: no proposals specified")
	}
	return nil
}

type Proposal struct {
	Raw         []byte      `json:"raw,omitempty"`
	ProposalNum uint8       `json:"proposal_num,omitempty"`
	ProtocolId  uint8       `json:"protocol_id,omitempty"`
	Spi         []byte      `json:"spi,omitempty"`
	Transforms  []Transform `json:"transforms,omitempty"`
}

type Transform struct {
	Raw        []byte      `json:"raw,omitempty"`
	Num        uint8       `json:"num,omitempty"`
	Attributes []Attribute `json:"attributes,omitempty"`
	// used in IKEv1
	IdV1 uint8 `json:"id_v1,omitempty"`
	// used in IKEv2
	Type uint8  `json:"type,omitempty"`
	Id   uint16 `json:"id,omitempty"`
}

type Attribute struct {
	Raw   []byte `json:"raw,omitempty"`
	Type  uint16 `json:"type"`
	Value []byte `json:"value"`
}
