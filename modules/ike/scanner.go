package ike

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Module implements the zgrab2.Module interface.
type Module struct {
}

type Flags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags

	// Verbosity flag
	Verbose bool `long:"ike-verbose" description:"Output additional information about the IKE exchange."`
	// IKE Version (1 or 2)
	Version uint16 `long:"ike-version" default:"1" description:"The IKE version to use."`
	// IKEv1 Mode ("aggressive" or "main")
	ModeV1 string `long:"ike-mode-v1" default:"aggressive" description:"Specify \"main\" or \"aggressive\" mode for IKEv1."`
	// Diffie-Hellman group to send in the initiator key exchange message
	DHGroup string `long:"ike-dh-group" default:"2" description:"The Diffie-Hellman group to be sent in the key exchange payload. 2: DH1024, 14: DH2048"`
	// ALL: Encryption algorithms
	ProposeEncAlgs string `long:"ike-enc" default:"des,3des,aes128,aes256" description:"Comma separated list of encryption algorithms to send in payload with builtin ALL"`
	// ALL: Hash algorithms
	ProposeHashAlgs string `long:"ike-hash" default:"md5,sha1,sha256" description:"Comma separated list of hash algorithms to send in payload with builtin ALL"`
	// ALL: Authentication methods
	ProposeAuthMethods string `long:"ike-auth" default:"psk,rsa_sig" description:"Comma separated list of authentication methods to send in payload with builtin ALL"`
	// ALL: Groups, TODO: make sure we can only propose one group in aggressive mode
	ProposeGroups string `long:"ike-group" default:"modp768,modp1024,modp1536,modp2048" description:"Comma separated list of groups to send in payload with builtin ALL"`
	// NthRound int `long:"ike-nth-round" default:"0" description:"If not 0, send the nth round of proposals (since there can be more than 127 proposals for safety)"`
	// BuiltIn specifies a built-in configuration that may overwrite other command-line options.
	Nonce string `long:"ike-nonce" default:"000102030405060708090a0b0c0d0e0f10111213" description:"Initiator nonce value to send in hex"`
	BuiltIn string `long:"ike-builtin" default:"RSA_SIGNATURE" description:"Use a built-in IKE config, overwriting other command-line IKE options."`
	Identity string `long:"ike-identity" default:"email:research-scan@sysnet.ucsd.edu" description:"The identity. See https://docs.strongswan.org/docs/5.9/config/identityParsing.html for parsing rules"`
	ProbeFile string `long:"ike-probe-file" default:"" description:"Write the initial initiator packet to file and exit. (This is useful for creating zmap probes.)"`
}

type Scanner struct {
	config *Flags

	idType uint8
	idData []byte
	groupNum uint16
	transforms []Transform
	nonce []byte
}

func RegisterModule() {
	var mod Module
	_, err := zgrab2.AddCommand("ike", "IKE", mod.Description(), 500, &mod)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns the default flags object to be filled in with the
// command-line arguments.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Scanner for IKE and IKEv2 (ISAKMP)"
}

// Validate flags
func (f *Flags) Validate(args []string) (err error) {
	_, _, idErr := ParseIdentity(f.Identity)
	if idErr != nil {
		log.Fatal(idErr)
		return zgrab2.ErrInvalidArguments
	}
	_, trErr := ParseTransforms(f)
	if trErr != nil {
		log.Fatal(trErr)
		return zgrab2.ErrInvalidArguments
	}
	_, grErr := group2Num(f.DHGroup)
	if grErr != nil {
		log.Fatal(grErr)
		return zgrab2.ErrInvalidArguments
	}
	_, nErr := ParseNonce(f.Nonce)
	if nErr != nil {
		log.Fatal(nErr)
		return zgrab2.ErrInvalidArguments
	}
	if (f.Version != 1 && f.Version != 2) {
		log.Fatalf("Bad IKE version %d", f.Version)
		return zgrab2.ErrInvalidArguments
	}
	if (f.ModeV1 != "aggressive" && f.ModeV1 != "main") {
		log.Fatal("Mode must be either aggressive or main")
		return zgrab2.ErrInvalidArguments
	}
	return nil
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner instance with the flags from the command
// line.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	idType, idData, err := ParseIdentity(f.Identity)
	if err != nil {
		panic(err)
	}
	s.idType = idType
	s.idData = idData
	transforms, err := ParseTransforms(f)
	if err != nil {
		panic(err)
	}
	groupNum, err := group2Num(f.DHGroup)
	if err != nil {
		panic(err)
	}
	nonce, err := ParseNonce(f.Nonce)
	if err != nil {
		panic(err)
	}
	s.groupNum = groupNum
	s.transforms = transforms
	s.nonce = nonce

	s.config = f

	if f.Verbose {
		log.Info("CONFIGURATION:")
		log.Infof("IKE Version: %d", f.Version)
		if f.Version == 1 {
			log.Infof("IKEv1 mode: %s", f.ModeV1)
		}
		log.Infof("Initial DH Group: %d", s.groupNum)
		log.Infof("IKE identity: %s", f.Identity)
		log.Infof("IKE Built-in: %s", f.BuiltIn)
		log.Infof("IKE Nonce (hex): %s", f.Nonce)
		log.Infof("IKE Nonce length: %d bytes", len(f.Nonce) / 2) // 2 hex digit = 1 byte
	}

	return nil
}

// InitPerSender does nothing in this module.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the configured name for the Scanner.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifer for the scanner.
func (s *Scanner) Protocol() string {
	return "ike"
}

func group2Num(groupName string) (uint16, error) {
	i, err := strconv.Atoi(groupName)
	if err == nil {
		return uint16(i), nil
	}
	groupNum, ok := GroupNameMap[groupName]
	if !ok {
		keys := make([]string, 0, len(GroupNameMap))
		for k := range GroupNameMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		validGroups := strings.Join(keys, ",")
		return 0, fmt.Errorf("Bad --ike-dh-group=%s. Valid values are numbers or one of %s", groupName, validGroups)
	}
	return groupNum, nil
}

func (s *Scanner) ConfigFromFlags(flags *Flags) *InitiatorConfig {
	ret := new(InitiatorConfig)
	ret.Version = flags.Version
	ret.ModeV1 = flags.ModeV1
	ret.DHGroup = s.groupNum
	ret.Proposals = []Proposal{} // TODO: support customizing this
	ret.KexValues = [][]byte{} // TODO: support customizing this
	ret.BuiltIn = flags.BuiltIn
	ret.IdentityType = s.idType
	ret.IdentityData = s.idData
	ret.AllTransforms = s.transforms
	ret.ProbeFile = flags.ProbeFile
	ret.NonceData = s.nonce
	return ret
}

func TryGetScanStatus(err error) zgrab2.ScanStatus {
	switch err {
	case ErrNotificationV1, ErrNotificationV2:
		return zgrab2.SCAN_APPLICATION_ERROR
	default:
		return zgrab2.TryGetScanStatus(err)
	}
}

func (s *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var err error
	conn, err := t.OpenUDP(&s.config.BaseFlags, &s.config.UDPFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()
	// log.Println("Flag", s.config)
	config := s.ConfigFromFlags(s.config)
	// log.Println("IKE config", config)
	config.ConnLog = new(HandshakeLog)
	_, err = NewInitiatorConn(conn, "", config)
	if err != nil {
		return TryGetScanStatus(err), config.ConnLog, err
	}
	return zgrab2.SCAN_SUCCESS, config.ConnLog, nil
}
