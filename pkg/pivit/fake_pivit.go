package pivit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

type fakeYubikey struct {
	isOpen          bool
	privateKey      crypto.PrivateKey
	attestationCert *x509.Certificate
	serialNumber    string
	managementKey   []byte
	pin             string
	puk             string
	slots           map[piv.Slot]*slotContent
	metadata        *piv.Metadata
}

type slotContent struct {
	privateKey *crypto.PrivateKey
	cert       *x509.Certificate
}

func testYubikey() (*fakeYubikey, error) {
	fakeSerial := "123456789"
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	subject := pkix.Name{
		Organization:       []string{"Fake Yubico."},
		OrganizationalUnit: []string{},
		SerialNumber:       fakeSerial,
		CommonName:         "Fake Pivit",
	}
	extKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, errors.Wrap(err, "create certificate random serial")
	}

	cert := &x509.Certificate{
		Subject:         subject,
		SerialNumber:    serial,
		DNSNames:        []string{},
		EmailAddresses:  []string{},
		IPAddresses:     []net.IP{},
		URIs:            []*url.URL{},
		KeyUsage:        x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     extKeyUsage,
		ExtraExtensions: []pkix.Extension{},
		IsCA:            true,
		NotBefore:       time.Now(),
		NotAfter:        time.Now().AddDate(0, 0, 2),
	}
	data, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	attestationCert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}

	return &fakeYubikey{
		isOpen:          true,
		privateKey:      privateKey,
		attestationCert: attestationCert,
		managementKey:   piv.DefaultManagementKey,
		pin:             piv.DefaultPIN,
		puk:             piv.DefaultPUK,
		slots:           make(map[piv.Slot]*slotContent),
		metadata: &piv.Metadata{
			ManagementKey: &piv.DefaultManagementKey,
		},
	}, nil
}

func (f *fakeYubikey) Close() error {
	if !f.isOpen {
		return errors.New("already closed")
	}
	f.isOpen = false
	return nil
}

func (f *fakeYubikey) AttestationCertificate() (*x509.Certificate, error) {
	if f.attestationCert != nil {
		return f.attestationCert, nil
	}
	return nil, errors.New("attestation certificate not found")
}

func (f *fakeYubikey) Attest(slot piv.Slot) (*x509.Certificate, error) {
	s, ok := f.slots[slot]
	if !ok {
		return nil, errors.New("key not found")
	}
	fakeSerial := "123456789"
	subject := pkix.Name{
		Organization:       []string{"Fake Yubico."},
		OrganizationalUnit: []string{},
		SerialNumber:       fakeSerial,
		CommonName:         "Fake Pivit",
	}
	extKeyUsage := []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, errors.Wrap(err, "create certificate random serial")
	}

	template := &x509.Certificate{
		Subject:         subject,
		SerialNumber:    serial,
		DNSNames:        []string{},
		EmailAddresses:  []string{},
		IPAddresses:     []net.IP{},
		URIs:            []*url.URL{},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     extKeyUsage,
		ExtraExtensions: []pkix.Extension{},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().AddDate(0, 0, 1),
	}

	var data []byte
	switch priv := (*s.privateKey).(type) {
	case *ecdsa.PrivateKey:
		pub := priv.PublicKey
		data, err = x509.CreateCertificate(rand.Reader, template, f.attestationCert, &pub, f.privateKey)
	case *rsa.PrivateKey:
		pub := priv.PublicKey
		data, err = x509.CreateCertificate(rand.Reader, template, f.attestationCert, &pub, f.privateKey)
	case *ed25519.PrivateKey:
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("bad key type")
		}
		data, err = x509.CreateCertificate(rand.Reader, template, f.attestationCert, &pub, f.privateKey)
	default:
		return nil, errors.New("bad key type")
	}
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(data)
}

func (f *fakeYubikey) PrivateKey(slot piv.Slot, publicKey crypto.PublicKey, _ piv.KeyAuth) (crypto.PrivateKey, error) {
	if _, ok := f.slots[slot]; !ok {
		return nil, errors.New("key not found")
	}
	content := f.slots[slot]
	switch priv := (*content.privateKey).(type) {
	case *rsa.PrivateKey:
		rsaPub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("wrong key type")
		}
		if &priv.PublicKey != rsaPub {
			return nil, errors.New("wrong public key")
		}
	case *ecdsa.PrivateKey:
		ecdsaPub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("wrong key type")
		}
		if !ecdsaPub.Equal(priv.Public()) {
			return nil, errors.New("wrong public key")
		}
	case ed25519.PrivateKey:
		ed25519Pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("bad key type")
		}
		if ed25519Pub.Equal(publicKey) {
			return nil, errors.New("wrong public key")
		}
	}
	return *content.privateKey, nil
}

func (f *fakeYubikey) Certificate(slot piv.Slot) (*x509.Certificate, error) {
	if _, ok := f.slots[slot]; !ok {
		return nil, errors.New("key not found")
	}
	return f.slots[slot].cert, nil
}

func (f *fakeYubikey) SetManagementKey(oldKey, newKey []byte) error {
	if !bytes.Equal(f.managementKey[:], oldKey[:]) {
		return errors.New("wrong management key")
	}
	f.managementKey = newKey
	return nil
}

func (f *fakeYubikey) Metadata(pin string) (*piv.Metadata, error) {
	if f.pin != pin {
		return nil, errors.New("wrong PIN")
	}
	return f.metadata, nil
}

func (f *fakeYubikey) SetMetadata(managementKey []byte, metadata *piv.Metadata) error {
	if !bytes.Equal(f.managementKey[:], managementKey[:]) {
		return errors.New("wrong management key")
	}
	f.metadata = metadata
	return nil
}

func (f *fakeYubikey) Reset() error {
	f.pin = piv.DefaultPIN
	f.puk = piv.DefaultPUK
	f.managementKey = piv.DefaultManagementKey
	f.slots = make(map[piv.Slot]*slotContent)
	return nil
}

func (f *fakeYubikey) SetPIN(oldPIN, newPIN string) error {
	if f.pin != oldPIN {
		return errors.New("wrong PIN")
	}
	f.pin = newPIN
	return nil
}

func (f *fakeYubikey) SetPUK(oldPUK, newPUK string) error {
	if f.puk != oldPUK {
		return errors.New("wrong PUK")
	}
	f.puk = newPUK
	return nil
}

func (f *fakeYubikey) SetCertificate(managementKey []byte, slot piv.Slot, certificate *x509.Certificate) error {
	if !bytes.Equal(f.managementKey[:], managementKey[:]) {
		return errors.New("wrong management key")
	}
	if _, ok := f.slots[slot]; !ok {
		return errors.New("key not found")
	}
	content := f.slots[slot]
	if content.privateKey == nil {
		return errors.New("key not set")
	}
	priv := content.privateKey
	switch p := (*priv).(type) {
	case *ecdsa.PrivateKey:
		if !p.PublicKey.Equal(certificate.PublicKey) {
			return errors.New("keys don't match")
		}
	case *rsa.PrivateKey:
		if !p.PublicKey.Equal(certificate.PublicKey) {
			return errors.New("keys don't match")
		}
	case *ed25519.PrivateKey:
		pub, ok := p.Public().(ed25519.PublicKey)
		if !ok {
			return errors.New("bad key type")
		}
		if !pub.Equal(certificate.PublicKey) {
			return errors.New("keys don't match")
		}
	}
	content.cert = certificate
	return nil
}

func (f *fakeYubikey) GenerateKey(managementKey []byte, slot piv.Slot, key piv.Key) (crypto.PublicKey, error) {
	if !bytes.Equal(f.managementKey[:], managementKey[:]) {
		return nil, errors.New("wrong management key")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	priv := crypto.PrivateKey(privateKey)

	if err != nil {
		return nil, err
	}
	content := &slotContent{
		privateKey: &priv,
		cert:       nil,
	}
	f.slots[slot] = content
	return &privateKey.PublicKey, nil
}

func (f *fakeYubikey) Version() piv.Version {
	return piv.Version{
		Major: 4,
		Minor: 5,
		Patch: 0,
	}
}

var _ Pivit = (*fakeYubikey)(nil)

type promptReader struct {
	pin   string
	index int
}

func (p2 *promptReader) Read(p []byte) (n int, err error) {
	for i, b := range []byte(p2.pin[p2.index:]) {
		p2.index++
		p[i] = b
		if b == '\n' {
			break
		}
	}
	return p2.index, nil
}

func (p2 *promptReader) Close() error {
	return nil
}

var _ io.ReadCloser = (*promptReader)(nil)

func patchPivVerify(yubikey *fakeYubikey) {
	verify = func(attestationCert, slotCert *x509.Certificate) (*piv.Attestation, error) {
		s, _ := strconv.Atoi(yubikey.serialNumber)
		return &piv.Attestation{
			Version:     yubikey.Version(),
			Serial:      uint32(s),
			Formfactor:  piv.FormfactorUSBCNano,
			PINPolicy:   piv.PINPolicyNever,
			TouchPolicy: piv.TouchPolicyAlways,
			Slot:        piv.Slot{},
		}, nil
	}
}

func unpatchPinVerify() {
	verify = piv.Verify
}
