package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func readCertificate(path string) *x509.Certificate {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal("read CA certificate: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		fatal("decode CA certificate: no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fatal("parse CA certificate: %v", err)
	}
	return cert
}

func readSigner(path string) ed25519.PrivateKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal("read CA key: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		fatal("decode CA key: no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fatal("parse CA key: %v", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		fatal("CA key is %T, expected Ed25519", key)
	}
	return edKey
}

func writePrivate(path string, key ed25519.PrivateKey) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fatal("marshal private key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		fatal("write private key: %v", err)
	}
}

func main() {
	if len(os.Args) != 6 {
		fatal("usage: %s CA_CERT CA_KEY OUT_CERT OUT_KEY SAN_CSV", os.Args[0])
	}
	caCert := readCertificate(os.Args[1])
	caKey := readSigner(os.Args[2])
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generate server key: %v", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		fatal("generate serial: %v", err)
	}
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	if caCert.NotAfter.Before(notAfter) {
		notAfter = caCert.NotAfter.Add(-time.Minute)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{CommonName: "talos-csr-signer"},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, san := range strings.Split(os.Args[5], ",") {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, publicKey, caKey)
	if err != nil {
		fatal("sign server certificate: %v", err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		fatal("parse generated server certificate: %v", err)
	}
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		fatal("verify generated server certificate: %v", err)
	}
	if err := os.WriteFile(os.Args[3], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		fatal("write certificate: %v", err)
	}
	writePrivate(os.Args[4], privateKey)
}
