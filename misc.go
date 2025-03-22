package gosplit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

func isHandshake(buf []byte) bool {
	// TODO SSL is no longer supported by the tls package
	//  may need to see about implementing it manually
	// https://tls12.xargs.org/#client-hello/annotated
	if len(buf) >= 2 && buf[0] == 0x16 && buf[1] == 0x03 {
		return true
	}
	return false
}

func getVictimAddr(c net.Conn) (vA VictimAddr, err error) {
	if vA.IP, vA.Port, err = net.SplitHostPort(c.RemoteAddr().String()); err != nil {
		err = fmt.Errorf("error parsing victim address information: %w", err)
	}
	return
}

// GenSelfSignedCert generates a X509 certificate with:
//
// - Random RSA key of 2048 bits
// - Expiration date one year into the future
// - Not before of the time of generation
//
// Reference: https://go.dev/src/crypto/tls/generate_cert.go
func GenSelfSignedCert(subject pkix.Name, ips []net.IP, dnsNames []string) (*tls.Certificate, error) {

	priv, err := rsa.GenerateKey(rand.Reader, 2048)

	keyUsage := x509.KeyUsageDigitalSignature
	keyUsage |= x509.KeyUsageKeyEncipherment

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           ips,
		DNSNames:              dnsNames,
	}

	// create the self-signed certificate and private key
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		err = fmt.Errorf("error creating certificate: %w", err)
		return nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		err = fmt.Errorf("error marshalling private key: %w", err)
		return nil, err
	}

	// pem encode the certificate and key
	derBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	var crt tls.Certificate
	if crt, err = tls.X509KeyPair(derBytes, privBytes); err != nil {
		err = fmt.Errorf("error parsing certificate: %w", err)
		return nil, err
	}

	return &crt, err
}

func WritePEM(crt tls.Certificate, crtWriter, keyWriter io.Writer) (err error) {

	if err = pem.Encode(crtWriter, &pem.Block{Type: "CERTIFICATE", Bytes: crt.Certificate[0]}); err != nil {
		err = fmt.Errorf("error writing certificate: %w", err)
		return
	}

	var pB []byte
	if pB, err = x509.MarshalPKCS8PrivateKey(crt.PrivateKey); err != nil {
		err = fmt.Errorf("error marshalling private key: %w", err)
		return
	}

	if err = pem.Encode(keyWriter, &pem.Block{Type: "PRIVATE KEY", Bytes: pB}); err != nil {
		err = fmt.Errorf("error writing private key: %w", err)
	}

	return

}
