// Copyright 2019 The shrub.fr Authors.
// Use of this source code is governed by the CC0 1.0 Universal license
// that can be found at https://creativecommons.org/publicdomain/zero/1.0/

package mkcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

const rootName = "rootCA.pem"
const rootKeyName = "rootCA-key.pem"

var userAndHostname string
var shrubCA string           // <user's home directory>/.shrubgateway
var caCert *x509.Certificate // certificate of the local CA
var caKey crypto.PrivateKey  // private key of the local CA

// init loads in memory the certificate (in caCert) and the private key
// (in caKey) of the local CA. If the local CA is not in the directory shrubCA,
// a new local CA is created first.
//
// init is derived from the method loadCA at
// https://github.com/FiloSottile/mkcert/blob/master/cert.go
func init() {
	u, _ := user.Current()
	if u != nil {
		userAndHostname = u.Username + "@"
	}
	out, _ := exec.Command("hostname").Output()
	userAndHostname += strings.TrimSpace(string(out))

	homeDir, err := os.UserHomeDir()
	fatalIfErr(err, "failed to find the user's home directory")
	shrubCA = filepath.Join(homeDir, ".shrubgateway")

	if _, err := os.Stat(filepath.Join(shrubCA, rootName)); os.IsNotExist(err) {
		newCA()
	} else {
		log.Printf("Using the local CA at \"%s\"\n", shrubCA)
	}

	certPEMBlock, err := ioutil.ReadFile(filepath.Join(shrubCA, rootName))
	fatalIfErr(err, "failed to read the CA certificate")
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
	}
	caCert, err = x509.ParseCertificate(certDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA certificate")

	keyPEMBlock, err := ioutil.ReadFile(filepath.Join(shrubCA, rootKeyName))
	fatalIfErr(err, "failed to read the CA key")
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil || keyDERBlock.Type != "PRIVATE KEY" {
		log.Fatalln("ERROR: failed to read the CA key: unexpected content")
	}
	caKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA key")
}

// GetCertificate creates a new certificate valid for the name cl.ServerName,
// using the local CA loaded in memory by init
//
// GetCertificate is derived from the method makeCert at
// https://github.com/FiloSottile/mkcert/blob/master/cert.go
func GetCertificate(cl *tls.ClientHelloInfo) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"shrubgateway local certificate"},
			OrganizationalUnit: []string{userAndHostname},
		},

		NotAfter:  time.Now().AddDate(0, 0, 20),
		NotBefore: time.Now().AddDate(0, 0, -1),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	tpl.DNSNames = append(tpl.DNSNames, cl.ServerName)

	pub := priv.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &pub, caKey)
	if err != nil {
		return nil, err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})

	certificate, err := tls.X509KeyPair(certPEM, privPEM)
	return &certificate, err
}

// newCA creates a new local CA in the directory shrubCA
//
// newCA is derived from the method newCA at
// https://github.com/FiloSottile/mkcert/blob/master/cert.go
func newCA() {
	err := os.MkdirAll(shrubCA, 0700)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalIfErr(err, "failed to generate the CA key")
	pub := priv.PublicKey

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")

	spkiASN1, err := x509.MarshalPKIXPublicKey(&pub)
	fatalIfErr(err, "failed to encode public key")

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	fatalIfErr(err, "failed to decode public key")

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"shrubgateway local CA"},
			OrganizationalUnit: []string{userAndHostname},

			// The CommonName is required by iOS to show the certificate in the
			// "Certificate Trust Settings" menu.
			// https://github.com/FiloSottile/mkcert/issues/47
			CommonName: "shrubgateway " + userAndHostname,
		},
		SubjectKeyId: skid[:],

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now().AddDate(0, 0, -1),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,

		// for security reasons the local CA generated is restricted
		// to subdomains of ".localhost"
		PermittedDNSDomains: []string{".localhost"},
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &pub, priv)
	fatalIfErr(err, "failed to generate CA certificate")

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode CA key")
	err = ioutil.WriteFile(filepath.Join(shrubCA, rootKeyName), pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	fatalIfErr(err, "failed to save CA key")

	err = ioutil.WriteFile(filepath.Join(shrubCA, rootName), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save CA key")

	log.Printf("Created a new local CA at \"%s\"\n", shrubCA)
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}
