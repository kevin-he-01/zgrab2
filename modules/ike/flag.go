package ike

import (
	"encoding/hex"
	"encoding/json"
	// "flag"
	"strings"
)

var pkgConfig IKEConfig

type IKEConfig struct {
	Verbose   bool
	Version   int
	ModeV1    string
	DHGroup   int
	Proposals ProposalList
	KexValues KexValueList
	BuiltIn   string
	ProbeFile string
}

type ProposalList struct {
	Proposals []Proposal
}

func (pList *ProposalList) MarshalJSON() ([]byte, error) {
	return json.Marshal(pList.Proposals)
}

func (pList *ProposalList) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &pList)
}

func (pList *ProposalList) String() string {
	if enc, err := pList.MarshalJSON(); err != nil {
		return err.Error()
	} else {
		return string(enc)
	}
}

func (pList *ProposalList) Set(value string) error {
	if err := pList.UnmarshalJSON([]byte(value)); err != nil {
		return err
	} else {
		return nil
	}
}

func (pList *ProposalList) Get() []Proposal {
	if len(pList.Proposals) == 0 {
		return []Proposal{}
	} else {
		return pList.Proposals
	}
}

type KexValueList struct {
	KexValues [][]byte
}

func (kList *KexValueList) String() string {
	var sList []string
	for _, s := range kList.KexValues {
		sList = append(sList, hex.EncodeToString(s))
	}

	return strings.Join(sList, ",")
}

func (kList *KexValueList) Set(value string) error {
	for _, kexValue := range strings.Split(value, ",") {
		if b, err := hex.DecodeString(kexValue); err != nil {
			return err
		} else {
			kList.KexValues = append(kList.KexValues, b)
		}
	}

	return nil
}

func (kList *KexValueList) Get() [][]byte {
	if len(kList.KexValues) == 0 {
		return [][]byte{}
	} else {
		return kList.KexValues
	}
}

// DEPRECATED: fetch flags in Zgrab2 by putting them in struct Flags in modules/ike/scanner.go
func init() {
	// flag.Var(&pkgConfig.Proposals, "ike-proposals", "A json-encoded list of proposals for the initiator security association payload. See the build-proposal.py tool.")
	// flag.Var(&pkgConfig.KexValues, "ike-kex-values", "A comma-separated list of hex-encoded public key exchange values for the initiator key exchange payload.")
	// flag.StringVar(&pkgConfig.ProbeFile, "ike-probe-file", "", "Write the initial initiator packet to file and exit. (This is useful for creating zmap probes.)")
}
