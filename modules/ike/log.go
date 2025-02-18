package ike

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"net"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

type CryptoInfo struct {
	DHExponential         *big.Int `json:"dh_exponent,omitempty"`
	DHSharedSecret        []byte   `json:"dh_shared_secret,omitempty"`
	// Called SKEYSEED in IKEv2, SKEYID in IKEv1
	SKEYSEED              []byte   `json:"skeyseed,omitempty"`
	SK_d                  []byte   `json:"sk_d,omitempty"`
	SK_ai                 []byte   `json:"sk_ai,omitempty"`
	SK_ar                 []byte   `json:"sk_ar,omitempty"`
	SK_ei                 []byte   `json:"sk_ei,omitempty"`
	SK_er                 []byte   `json:"sk_er,omitempty"`
	SK_pi                 []byte   `json:"sk_pi,omitempty"`
	SK_pr                 []byte   `json:"sk_pr,omitempty"`
	// Contents hashed into HASH_R for IKEv1, signed octets in IKEv2
	ResponderSignedOctets []byte   `json:"signed_octets,omitempty"`
	// Only in IKEv1
	HASH_R 			      []byte   `json:"hash_r,omitempty"`
}

type HandshakeLog struct {
	// IKEv1 Main Mode
	InitiatorMainSA *IkeMessage `json:"initiator_main_sa,omitempty"`
	ResponderMainSA *IkeMessage `json:"responder_main_sa,omitempty"`
	InitiatorMainKE *IkeMessage `json:"initiator_main_ke,omitempty"`
	ResponderMainKE *IkeMessage `json:"responder_main_ke,omitempty"`

	// IKEv1 Aggressive Mode
	InitiatorAggressive *IkeMessage `json:"initiator_aggr,omitempty"`
	ResponderAggressive *IkeMessage `json:"responder_aggr,omitempty"`

	// IKEv2 IKE_SA_INIT
	InitiatorSAInit *IkeMessage `json:"initiator_ike_sa_init,omitempty"`
	ResponderSAInit *IkeMessage `json:"responder_ike_sa_init,omitempty"`

	// IKEv2 IKE_AUTH
	InitiatorAuth          *IkeMessage   `json:"initiator_ike_auth,omitempty"`
	InitiatorAuthEncrypted *IkeMessage   `json:"initiator_ike_auth_enc,omitempty"`
	ResponderAuth          *IkeMessage   `json:"responder_ike_auth,omitempty"`
	ResponderAuthEncrypted *IkeMessage   `json:"responder_ike_auth_enc,omitempty"`
	ResponderAuthFragments []*IkeMessage `json:"responder_ike_auth_frag,omitempty"` // (encrypted) fragments

	// All
	ErrorNotification *IkeMessage   `json:"error_notification,omitempty"`
	Unexpected        []*IkeMessage `json:"unexpected_messages,omitempty"`
	Retransmit        []*IkeMessage `json:"retransmits,omitempty"`
	ErrorOrigin       string        `json:"error_origin,omitempty"` // Origin (JSON tag name) of error_notification log (Limitation: only exist in EAP scans, where this might be ambiguous)

	UnparsableRaw []byte `json:"unparsable_raw,omitempty"` // Raw contents of unparsable messages

	Crypto *CryptoInfo `json:"crypto,omitempty"`
}

type IkeMessage struct {
	Raw          []byte
	InitiatorSPI []byte
	ResponderSPI []byte
	Payloads     []Payload
}

func (msg *IkeMessage) MarshalJSON() ([]byte, error) {
	aux := []interface{}{}

	for _, p := range msg.Payloads {
		// IKEv1 or IKEv2
		if pa, ok := p.(*SecurityAssociation); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*KeyExchange); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*Identification); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*Nonce); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*VendorId); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*Notify); ok {
			aux = append(aux, *pa)
		}

		if pa, ok := p.(*Certificate); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*CertificateRequest); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*Authentication); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*Signature); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*Hash); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*EAP); ok {
			aux = append(aux, *pa)
		}

		if pa, ok := p.(*EmptyPayload); ok {
			aux = append(aux, *pa)
		}

	}

	aux2 := struct {
		Raw          []byte        `json:"raw,omitempty"`
		InitiatorSPI []byte        `json:"initiator_spi,omitempty"`
		ResponderSPI []byte        `json:"responder_spi,omitempty"`
		Proposals    []interface{} `json:"payloads,omitempty"`
	}{
		Raw:          msg.Raw,
		InitiatorSPI: msg.InitiatorSPI,
		ResponderSPI: msg.ResponderSPI,
		Proposals:    aux,
	}
	return json.Marshal(&aux2)
}

type Payload interface{}

func (msg *ikeMessage) MakeLog() (m *IkeMessage) {
	m = new(IkeMessage)
	m.InitiatorSPI = append([]byte{}, msg.hdr.initiatorSPI[:]...)
	m.ResponderSPI = append([]byte{}, msg.hdr.responderSPI[:]...)
	m.Raw = append(m.Raw, msg.marshal()...)
	for _, payload := range msg.payloads {
		m.Payloads = append(m.Payloads, payload.MakeLogAll())
	}
	return
}

// Includes unrecognized payloads
func (p *payload) MakeLogAll() Payload {
	pLog := p.MakeLog()
	emp, ok := pLog.(*EmptyPayload)
	if ok {
		switch p.payloadType {
		case ENCRYPTED_AND_AUTHENTICATED_FRAGMENT_V2:
			emp.Name = "encrypted_fragment"
		case ENCRYPTED_V2:
			emp.Name = "encrypted"
		case TRAFFIC_SELECTOR_INITIATOR_V2:
			emp.Name = "traffic_selector_initiator"
		case TRAFFIC_SELECTOR_RESPONDER_V2:
			emp.Name = "traffic_selector_responder"
		default:
			emp.Name = fmt.Sprintf("stub_%d", p.payloadType)
		}
	}
	return pLog
}

func (p *payload) MakeLog() Payload {

	switch p.payloadType {
	case NO_NEXT_PAYLOAD:
		return new(EmptyPayload)
		//  IKEv1
	case SECURITY_ASSOCIATION_V1:
		if pa, ok := p.body.(*payloadSecurityAssociationV1); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case KEY_EXCHANGE_V1:
		if pa, ok := p.body.(*payloadKeyExchangeV1); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case IDENTIFICATION_V1:
		if pa, ok := p.body.(*payloadIdentification); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}

	case CERTIFICATE_V1:
		if pa, ok := p.body.(*payloadCertificate); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case CERTIFICATE_REQUEST_V1:
		if pa, ok := p.body.(*payloadCertificateRequest); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case HASH_V1:
		if pa, ok := p.body.(*payloadHashV1); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case SIGNATURE_V1:
		if pa, ok := p.body.(*payloadSignatureV1); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}

	case NONCE_V1:
		if pa, ok := p.body.(*payloadNonce); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case NOTIFICATION_V1:
		if pa, ok := p.body.(*payloadNotifyV1); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	/*
	   case DELETE_V1:
	*/
	case VENDOR_ID_V1:
		if pa, ok := p.body.(*payloadVendorId); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
		//  IKEv2
	case SECURITY_ASSOCIATION_V2:
		if pa, ok := p.body.(*payloadSecurityAssociationV2); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case KEY_EXCHANGE_V2:
		if pa, ok := p.body.(*payloadKeyExchangeV2); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case IDENTIFICATION_INITIATOR_V2:
		if pa, ok := p.body.(*payloadIdentification); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case IDENTIFICATION_RESPONDER_V2:
		if pa, ok := p.body.(*payloadIdentification); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}

	case CERTIFICATE_V2:
		if pa, ok := p.body.(*payloadCertificate); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case CERTIFICATE_REQUEST_V2:
		if pa, ok := p.body.(*payloadCertificateRequest); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case AUTHENTICATION_V2:
		if pa, ok := p.body.(*payloadAuthentication); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}

	case NONCE_V2:
		if pa, ok := p.body.(*payloadNonce); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case NOTIFY_V2:
		if pa, ok := p.body.(*payloadNotifyV2); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	/*
	   case DELETE_V2:
	*/
	case VENDOR_ID_V2:
		if pa, ok := p.body.(*payloadVendorId); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case EXTENSIBLE_AUTHENTICATION_V2:
		if pa, ok := p.body.(*payloadEAP); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	}
	return new(EmptyPayload)
}

type Certificate struct {
	Name       string            `json:"type,omitempty"`
	Encoding   uint8             `json:"encoding,omitempty"`
	CertData   []byte            `json:"data,omitempty"`
	X509Parsed *x509.Certificate `json:"x509_parsed,omitempty"`
	X509Error  string            `json:"error,omitempty"`
}

type CertificateRequest struct {
	Name     string `json:"type,omitempty"`
	Raw      []byte `json:"raw,omitempty"`
	Encoding uint8  `json:"encoding,omitempty"`
	CertAuth []byte `json:"ca,omitempty"`
}

type Hash struct {
	Name     string `json:"type,omitempty"`
	Raw      []byte `json:"raw,omitempty"`
	HashData []byte `json:"data,omitempty"`
}

type Authentication struct {
	Name   string `json:"type,omitempty"`
	Raw    []byte `json:"raw,omitempty"`
	Method uint8  `json:"method,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

func (p *payloadCertificate) MakeLog() *Certificate {
	cr := new(Certificate)
	// cr.Raw = append(cr.Raw, p.marshal()...)

	cr.Name = "certificate"
	cr.Encoding = p.encoding
	cr.CertData = p.certificateData
	if cr.Encoding == X509_CERTIFICATE_SIGNATURE_V2 {
		if parsed, err := x509.ParseCertificate(cr.CertData); err == nil {
			cr.X509Parsed = parsed
		} else {
			cr.X509Error = err.Error()
		}
	}

	return cr
}

func (p *payloadCertificateRequest) MakeLog() *CertificateRequest {
	cr := new(CertificateRequest)
	// cr.Raw = append(cr.Raw, p.marshal()...)

	cr.Name = "certificate_request"
	cr.Encoding = p.encoding
	cr.CertAuth = p.certificateAuth

	return cr
}

func (p *payloadHashV1) MakeLog() *Hash {
	ha := new(Hash)
	// ha.Raw = append(ha.Raw, p.marshal()...)

	ha.Name = "hash"
	ha.HashData = p.hashData

	return ha
}

func (p *payloadAuthentication) MakeLog() *Authentication {
	auth := new(Authentication)

	auth.Name = "authentication"
	auth.Method = p.authMethod
	auth.Data = p.authData

	return auth
}

type EmptyPayload struct {
	Name string `json:"type"`
}

type SecurityAssociation struct {
	Name      string     `json:"type,omitempty"`
	Raw       []byte     `json:"raw,omitempty"`
	Doi       uint32     `json:"doi,omitempty"`
	Situation []byte     `json:"situation,omitempty"`
	Proposals []Proposal `json:"proposals,omitempty"`
}

func (p *payloadSecurityAssociationV2) MakeLog() *SecurityAssociation {
	sa := new(SecurityAssociation)
	//sa.Raw = append(sa.Raw, p.marshal()...)

	sa.Proposals = make([]Proposal, len(p.proposals))
	for proposalidx, proposal := range p.proposals {
		sa.Proposals[proposalidx].Raw = append(sa.Proposals[proposalidx].Raw, proposal.raw...)
		sa.Proposals[proposalidx].ProposalNum = proposal.proposalNum
		sa.Proposals[proposalidx].ProtocolId = proposal.protocolId
		sa.Proposals[proposalidx].Spi = append(sa.Proposals[proposalidx].Spi, proposal.spi...)
		sa.Proposals[proposalidx].Transforms = make([]Transform, len(proposal.transforms))
		for transformidx, transform := range proposal.transforms {
			sa.Proposals[proposalidx].Transforms[transformidx].Raw = append(sa.Proposals[proposalidx].Transforms[transformidx].Raw, transform.raw...)
			sa.Proposals[proposalidx].Transforms[transformidx].Type = transform.transformType
			sa.Proposals[proposalidx].Transforms[transformidx].Id = transform.transformId
			sa.Proposals[proposalidx].Transforms[transformidx].Attributes = make([]Attribute, len(transform.attributes))
			for attributeidx, attribute := range transform.attributes {
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Raw = append(sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Raw, attribute.raw...)
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Type = attribute.attributeType
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Value = append(sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Value, attribute.attributeValue...)
			}
		}
	}

	sa.Name = "security_association"
	return sa
}

func (p *payloadSecurityAssociationV1) MakeLog() *SecurityAssociation {
	sa := new(SecurityAssociation)
	//sa.Raw = append(sa.Raw, p.marshal()...)
	sa.Doi = p.doi
	sa.Situation = append(sa.Situation, p.situation...)

	sa.Proposals = make([]Proposal, len(p.proposals))
	for proposalidx, proposal := range p.proposals {
		sa.Proposals[proposalidx].Raw = append(sa.Proposals[proposalidx].Raw, proposal.raw...)
		sa.Proposals[proposalidx].ProposalNum = proposal.proposalNum
		sa.Proposals[proposalidx].ProtocolId = proposal.protocolId
		sa.Proposals[proposalidx].Spi = append(sa.Proposals[proposalidx].Spi, proposal.spi...)
		sa.Proposals[proposalidx].Transforms = make([]Transform, len(proposal.transforms))
		for transformidx, transform := range proposal.transforms {
			sa.Proposals[proposalidx].Transforms[transformidx].Raw = append(sa.Proposals[proposalidx].Transforms[transformidx].Raw, transform.raw...)
			sa.Proposals[proposalidx].Transforms[transformidx].Num = transform.transformNum
			sa.Proposals[proposalidx].Transforms[transformidx].IdV1 = transform.transformId
			sa.Proposals[proposalidx].Transforms[transformidx].Attributes = make([]Attribute, len(transform.attributes))
			for attributeidx, attribute := range transform.attributes {
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Raw = append(sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Raw, attribute.raw...)
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Type = attribute.attributeType
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Value = append(sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Value, attribute.attributeValue...)
			}
		}
	}

	sa.Name = "security_association"
	return sa
}

type KeyExchange struct {
	Name            string `json:"type,omitempty"`
	Raw             []byte `json:"raw,omitempty"`
	DhGroup         uint16 `json:"dh_group,omitempty"`
	KeyExchangeData []byte `json:"kex_data,omitempty"`
}

func (p *payloadKeyExchangeV1) MakeLog() *KeyExchange {
	ke := new(KeyExchange)
	//ke.Raw = append(ke.Raw, p.marshal()...)
	//ke.DhGroup = p.dhGroup
	ke.KeyExchangeData = append(ke.KeyExchangeData, p.keyExchangeData...)
	ke.Name = "key_exchange"
	return ke
}

func (p *payloadKeyExchangeV2) MakeLog() *KeyExchange {
	ke := new(KeyExchange)
	//ke.Raw = append(ke.Raw, p.marshal()...)
	ke.DhGroup = p.dhGroup
	ke.KeyExchangeData = append(ke.KeyExchangeData, p.keyExchangeData...)
	ke.Name = "key_exchange"
	return ke
}

type Signature struct {
	Name          string `json:"type,omitempty"`
	Raw           []byte `json:"raw,omitempty"`
	SignatureData []byte `json:"sig_data,omitempty"`
}

func (p *payloadSignatureV1) MakeLog() *Signature {
	sig := new(Signature)
	//sig.Raw = append(sig.Raw, p.marshal()...)
	sig.SignatureData = append(sig.SignatureData, p.signatureData...)
	sig.Name = "signature"
	return sig
}

type Nonce struct {
	Name      string `json:"type,omitempty"`
	Raw       []byte `json:"raw,omitempty"`
	NonceData []byte `json:"nonce,omitempty"`
}

func (p *payloadNonce) MakeLog() *Nonce {
	no := new(Nonce)
	// no.Raw = append(no.Raw, p.marshal()...)
	no.NonceData = append(no.NonceData, p.nonceData...)
	no.Name = "nonce"
	return no
}

type VendorId struct {
	Name  string `json:"type,omitempty"`
	Raw   []byte `json:"raw,omitempty"`
	Id    []byte `json:"id,omitempty"`
	IdStr string `json:"id_string,omitempty"`
}

func (p *payloadVendorId) MakeLog() *VendorId {
	vi := new(VendorId)
	// vi.Raw = append(.Raw, p.marshal()...)
	vi.Id = append(vi.Id, p.id...)
	vi.IdStr = lookupVendorId(vi.Id)
	vi.Name = "vendor_id"
	return vi
}

type Identification struct {
	Name       string     `json:"type,omitempty"`
	Raw        []byte     `json:"raw,omitempty"`
	IdType     uint8      `json:"id_type,omitempty"`
	IdData     []byte     `json:"id_string,omitempty"`
	Ip         string     `json:"ip,omitempty"`
	DerName    *pkix.Name `json:"der_name,omitempty"`
	DerDN      string     `json:"der_dn,omitempty"`
	FQDN       string     `json:"fqdn,omitempty"`
	RFC822Addr string     `json:"rfc822_addr,omitempty"`
}

func (p *payloadIdentification) MakeLog() *Identification {
	id := new(Identification)
	// vi.Raw = append(.Raw, p.marshal()...)
	id.IdType = p.idType
	id.IdData = append(id.IdData, p.idData...)
	id.Name = "identification"
	switch id.IdType {
	case ID_FQDN_V2:
		id.FQDN = string(id.IdData)
	case ID_RFC822_ADDR_V2:
		id.RFC822Addr = string(id.IdData)
	case ID_IPV4_ADDR_V2:
		if len(id.IdData) == 4 {
			id.Ip = net.IP(id.IdData).String()
		}
	case ID_DER_ASN1_DN_V2:
		var rdnSeq pkix.RDNSequence
		if _, err := asn1.Unmarshal(id.IdData, &rdnSeq); err != nil {
			break
		}
		id.DerName = new(pkix.Name)
		id.DerName.FillFromRDNSequence(&rdnSeq)
		id.DerDN = id.DerName.String()
	}
	return id
}

type Notify struct {
	Name       string `json:"type,omitempty"`
	Raw        []byte `json:"raw,omitempty"`
	Doi        uint32 `json:"doi,omitempty"`
	ProtocolId uint8  `json:"protocol_id,omitempty"`
	NotifyType uint16 `json:"notify_type,omitempty"`
	Spi        []byte `json:"spi,omitempty"`
	NotifyData []byte `json:"notify_data,omitempty"`
}

func (p *payloadNotifyV1) MakeLog() *Notify {
	n := new(Notify)
	// n.Raw = append(n.Raw, p.marshal()...)
	n.Doi = p.doi
	n.ProtocolId = p.protocolId
	n.NotifyType = p.notifyType
	n.Spi = append(n.Spi, p.spi...)
	n.NotifyData = append(n.NotifyData, p.notifyData...)
	n.Name = "notification"
	return n
}

func (p *payloadNotifyV2) MakeLog() *Notify {
	n := new(Notify)
	// n.Raw = append(n.Raw, p.marshal()...)
	n.ProtocolId = p.protocolId
	n.NotifyType = p.notifyType
	n.Spi = append(n.Spi, p.spi...)
	n.NotifyData = append(n.NotifyData, p.notifyData...)
	n.Name = "notification"
	return n
}

type EAP struct {
	Name string `json:"type,omitempty"`
	Raw  []byte `json:"raw,omitempty"`
	Code uint8  `json:"code,omitempty"`
	Id   uint8  `json:"id,omitempty"`
	Type uint8  `json:"data_type,omitempty"`
	Data []byte `json:"data,omitempty"`
}

func (p *payloadEAP) MakeLog() *EAP {
	e := new(EAP)
	e.Name = "eap"
	e.Raw = p.raw
	e.Code = p.code
	e.Id = p.id
	e.Type = p.dataType
	e.Data = p.data
	return e
}
