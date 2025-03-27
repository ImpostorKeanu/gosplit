package gosplit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

type (
	// RSAPrivKey wraps rsa.PrivateKey, giving us a type to carry
	// configuration values and errors through RSAPrivKeyGenerator.
	//
	// Use NewRSAKey If standalone initialization is needed.
	RSAPrivKey struct {
		*rsa.PrivateKey
		bitLen int   // Bit length of the private key
		error  error // Error that occurred while generating the private key
	}
)

// NewRSAKey initializes a new instance and generates a new
// private key.
//
// Common bitLen values:
//
// - 1024
// - 2048
// - 3072
// - 4092
// - 512 (works, but less likely to be accepted by clients)
func NewRSAKey(bitLen int) (k *RSAPrivKey) {
	k = &RSAPrivKey{
		bitLen: bitLen,
		error:  checkRSABitLen(bitLen),
	}
	if k.error != nil {
		return
	}
	k.PrivateKey, k.error = rsa.GenerateKey(rand.Reader, bitLen)
	return
}

// Err returns any error that occurred while generating the
// private key.
func (r *RSAPrivKey) Err() error {
	return r.error
}

// BitLen returns the bit length of the private key.
func (r *RSAPrivKey) BitLen() int {
	return r.bitLen
}

// RSAPrivKeyGenerator starts a distinct routine that yields RSAPrivKey
// instances until the ctx is done.
func RSAPrivKeyGenerator(ctx context.Context, bitLen int) (c chan *RSAPrivKey, err error) {
	if err = checkRSABitLen(bitLen); err != nil {
		return
	}
	c = make(chan *RSAPrivKey)
	go func() {
		for {
			pK := NewRSAKey(bitLen)
			select {
			case <-ctx.Done():
				close(c)
				return
			case c <- pK:
			}
		}
	}()
	return c, err
}

// GenSelfSignedCert generates a X509 certificate with:
//
// - Random RSA key of keyBitSize bits
// - Expiration date one year into the future
// - Not before of the time of generation
//
// If priv is nil, an RSAPrivKey will be generated.
//
//
// Reference: https://go.dev/src/crypto/tls/generate_cert.go
func GenSelfSignedCert(subject pkix.Name, ips []net.IP, dnsNames []string, priv *RSAPrivKey) (*tls.Certificate, error) {

	var err error
	if priv == nil {
		if priv = NewRSAKey(1024); priv.error != nil {
			return nil, priv.error
		}
	}

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
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv.PrivateKey)
	if err != nil {
		err = fmt.Errorf("error creating certificate: %w", err)
		return nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv.PrivateKey)
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

// checkRSABitLen ensures that bitLen >= 0.
func checkRSABitLen(bitLen int) (err error) {
	if bitLen <= 0 {
		err = errors.New("bit length must be greater than zero")
	}
	return
}

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
