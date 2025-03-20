package gosplit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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
	if vA.VictimIP, vA.VictimPort, err = net.SplitHostPort(c.RemoteAddr().String()); err != nil {
		err = fmt.Errorf("error parsing victim address information: %w", err)
	}
	return
}

// GenCert generates a certificate using tls.ClientHelloInfo.ServerName
// as the name.
//
// Reference: https://go.dev/src/crypto/tls/generate_cert.go
func GenCert(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	keyUsage := x509.KeyUsageDigitalSignature
	keyUsage |= x509.KeyUsageKeyEncipherment
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"GoSplit"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if ip := net.ParseIP(info.ServerName); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, info.ServerName)
	}

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

	var crt tls.Certificate
	if crt, err = tls.X509KeyPair(derBytes, privBytes); err != nil {
		err = fmt.Errorf("error parsing certificate: %w", err)
		return nil, err
	}

	return &crt, err
}
