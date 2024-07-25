package pivit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"

	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
)

type fakeYubikey struct {
	isOpen          bool
	privateKey      crypto.PrivateKey
	attestationCert *x509.Certificate
	serialNumber    string
	managementKey   [24]byte
	pin             string
	puk             string
	slots           map[piv.Slot]*slotContent
	metadata        *piv.Metadata
}

type slotContent struct {
	privateKey crypto.PrivateKey
	cert       x509.Certificate
}

func testYubikey() (SecurityKey, error) {
	fakeSerial := "123456789"
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	subject := pkix.Name{
		Organization:       []string{"Fake Yubico."},
		OrganizationalUnit: []string{},
		SerialNumber:       fakeSerial,
		CommonName:         "Fake SecurityKey",
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
	}
	data, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	attestationCert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}

	return fakeYubikey{
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

func (f fakeYubikey) Close() error {
	if !f.isOpen {
		return errors.New("already closed")
	}
	f.isOpen = false
	return nil
}

func (f fakeYubikey) AttestationCertificate() (*x509.Certificate, error) {
	if f.attestationCert != nil {
		return f.attestationCert, nil
	}
	return nil, errors.New("attestation certificate not found")
}

func (f fakeYubikey) Attest(slot piv.Slot) (*x509.Certificate, error) {
	s := f.slots[slot]
	roots := x509.NewCertPool()
	roots.AddCert(&s.cert)
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	chains, err := s.cert.Verify(opts)
	if err != nil {
		return nil, err
	}
	return chains[0][0], nil
}

func (f fakeYubikey) PrivateKey(slot piv.Slot, publicKey crypto.PublicKey, _ piv.KeyAuth) (crypto.PrivateKey, error) {
	if _, ok := f.slots[slot]; !ok {
		return nil, errors.New("key not found")
	}
	content := f.slots[slot]
	if content.cert.PublicKey != publicKey {
		return nil, errors.New("wong public key")
	}
	return content.privateKey, nil
}

func (f fakeYubikey) Certificate(slot piv.Slot) (*x509.Certificate, error) {
	if _, ok := f.slots[slot]; !ok {
		return nil, errors.New("key not found")
	}
	return &f.slots[slot].cert, nil
}

func (f fakeYubikey) SetManagementKey(oldKey, newKey [24]byte) error {
	if f.managementKey != oldKey {
		return errors.New("wrong management key")
	}
	f.managementKey = newKey
	return nil
}

func (f fakeYubikey) Metadata(pin string) (*piv.Metadata, error) {
	if f.pin != pin {
		return nil, errors.New("wrong PIN")
	}
	return f.metadata, nil
}

func (f fakeYubikey) SetMetadata(managementKey [24]byte, metadata *piv.Metadata) error {
	if f.managementKey != managementKey {
		return errors.New("wrong management key")
	}
	f.metadata = metadata
	return nil
}

func (f fakeYubikey) Reset() error {
	f.pin = piv.DefaultPIN
	f.puk = piv.DefaultPUK
	f.managementKey = piv.DefaultManagementKey
	f.slots = make(map[piv.Slot]*slotContent)
	return nil
}

func (f fakeYubikey) SetPIN(oldPIN, newPIN string) error {
	if f.pin != oldPIN {
		return errors.New("wrong PIN")
	}
	f.pin = newPIN
	return nil
}

func (f fakeYubikey) SetPUK(oldPUK, newPUK string) error {
	if f.puk != oldPUK {
		return errors.New("wrong PUK")
	}
	f.puk = newPUK
	return nil
}

func (f fakeYubikey) SetCertificate(managementKey [24]byte, slot piv.Slot, certificate *x509.Certificate) error {
	if f.managementKey != managementKey {
		return errors.New("wrong management key")
	}
	if _, ok := f.slots[slot]; !ok {
		return errors.New("key not found")
	}
	content := f.slots[slot]
	if content.cert.PublicKey != certificate.PublicKey {
		return errors.New("keys don't match")
	}
	content.cert = *certificate
	return nil
}

func (f fakeYubikey) GenerateKey(managementKey [24]byte, slot piv.Slot, key piv.Key) (crypto.PublicKey, error) {
	if f.managementKey != managementKey {
		return nil, errors.New("wrong management key")
	}
	fakeSerial := "123456789"
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	subject := pkix.Name{
		Organization:       []string{"Fake Yubico."},
		OrganizationalUnit: []string{},
		SerialNumber:       fakeSerial,
		CommonName:         "Fake SecurityKey",
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
	}

	data, err := x509.CreateCertificate(rand.Reader, template, f.attestationCert, &privateKey.PublicKey, f.privateKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	content := &slotContent{
		privateKey: privateKey,
		cert:       *cert,
	}
	f.slots[slot] = content
	return cert.PublicKey, nil
}

func (f fakeYubikey) Version() piv.Version {
	return piv.Version{
		Major: 4,
		Minor: 5,
		Patch: 0,
	}
}

var _ SecurityKey = (*fakeYubikey)(nil)
