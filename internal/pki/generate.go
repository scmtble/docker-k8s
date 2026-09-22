package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultTalosSANS = "talos-csr-signer,localhost,127.0.0.1"
)

type certPair struct {
	Crt string `yaml:"crt"`
	Key string `yaml:"key"`
}

type secretsFile struct {
	Secrets struct {
		SecretboxEncryptionSecret string `yaml:"secretboxencryptionsecret"`
	} `yaml:"secrets"`
	TrustdInfo struct {
		Token string `yaml:"token"`
	} `yaml:"trustdinfo"`
	Certs map[string]certPair `yaml:"certs"`
}

type certificateRequest struct {
	Name          string
	CommonName    string
	Organizations []string
	DNSNames      []string
	IPAddresses   []net.IP
	Usages        []x509.ExtKeyUsage
}

type kubeconfigRequest struct {
	Name        string
	Certificate string
	Key         string
	Server      string
	User        string
}

// GenerateOptions configures PKI generation from a Talos secrets file.
type GenerateOptions struct {
	Source         string
	Output         string
	ClusterName    string
	APIServerURL   string
	TalosSANS      string
	KubernetesSANS string
}

// Generate writes a complete Kubernetes control-plane PKI directory.
func Generate(options GenerateOptions) error {
	source := options.Source
	output := options.Output
	clusterName := options.ClusterName
	if clusterName == "" {
		return errors.New("--cluster-name is required")
	}
	if options.APIServerURL == "" {
		return errors.New("--api-server-url is required")
	}
	if err := validateAPIServerURL(options.APIServerURL); err != nil {
		return err
	}
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("refusing to overwrite existing directory: %s", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check output directory: %w", err)
	}

	umask := syscall.Umask(0o077)
	defer syscall.Umask(umask)

	raw, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read secrets file: %w", err)
	}
	var secrets secretsFile
	if err := yaml.Unmarshal(raw, &secrets); err != nil {
		return fmt.Errorf("parse secrets file: %w", err)
	}

	for _, dir := range []string{"etcd", "kubeconfig", "talos"} {
		if err := os.MkdirAll(filepath.Join(output, dir), 0o700); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}

	decode := func(value string) []byte {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			panic(fmt.Errorf("decode base64 value: %w", err))
		}
		return decoded
	}
	writeSecret := func(path string, contents []byte, mode os.FileMode) {
		if err := os.WriteFile(path, contents, mode); err != nil {
			panic(fmt.Errorf("write %s: %w", path, err))
		}
	}
	importPair := func(sourceName, destination string) {
		pair, ok := secrets.Certs[sourceName]
		if !ok {
			panic(fmt.Errorf("missing certs.%s", sourceName))
		}
		writeSecret(destination+".crt", decode(pair.Crt), 0o644)
		writeSecret(destination+".key", decode(pair.Key), 0o600)
	}

	kubernetesCA := filepath.Join(output, "ca")
	frontProxyCA := filepath.Join(output, "front-proxy-ca")
	etcdCA := filepath.Join(output, "etcd", "ca")
	importPair("k8s", kubernetesCA)
	importPair("k8saggregator", frontProxyCA)
	importPair("etcd", etcdCA)

	talosPair, ok := secrets.Certs["os"]
	if !ok {
		return errors.New("missing certs.os")
	}
	talosCADirectory := filepath.Join(output, "talos")
	writeSecret(filepath.Join(talosCADirectory, "ca.crt"), decode(talosPair.Crt), 0o644)
	talosCAKey := strings.ReplaceAll(
		strings.ReplaceAll(string(decode(talosPair.Key)), "BEGIN ED25519 PRIVATE KEY", "BEGIN PRIVATE KEY"),
		"END ED25519 PRIVATE KEY",
		"END PRIVATE KEY",
	)
	talosCAKeyPEM := []byte(talosCAKey)
	talosCAKeyBlock, _ := pem.Decode(talosCAKeyPEM)
	if talosCAKeyBlock == nil {
		return errors.New("decode Talos CA key: no PEM block")
	}
	talosCAPrivateKey, err := x509.ParsePKCS8PrivateKey(talosCAKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("normalize Talos CA key: %w", err)
	}
	talosCADER, err := x509.MarshalPKCS8PrivateKey(talosCAPrivateKey)
	if err != nil {
		return fmt.Errorf("normalize Talos CA key: %w", err)
	}
	talosCAKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: talosCADER})
	writeSecret(filepath.Join(talosCADirectory, "ca.key"), talosCAKeyPEM, 0o600)
	writeSecret(filepath.Join(talosCADirectory, "signer.env"), []byte("TALOS_TOKEN="+secrets.TrustdInfo.Token+"\n"), 0o600)

	talosSANS := options.TalosSANS
	if talosSANS == "" {
		talosSANS = defaultTalosSANS
	}
	kubernetesSANS := options.KubernetesSANS
	if kubernetesSANS == "" {
		return errors.New("--kubernetes-sans is required")
	}
	apiserverDNS, apiserverIPs, err := parseSANS(kubernetesSANS)
	if err != nil {
		return fmt.Errorf("parse Kubernetes SANs: %w", err)
	}
	if err := issueTalosServerCertificate(
		filepath.Join(talosCADirectory, "ca.crt"),
		filepath.Join(talosCADirectory, "ca.key"),
		filepath.Join(talosCADirectory, "server.crt"),
		filepath.Join(talosCADirectory, "server.key"),
		talosSANS,
	); err != nil {
		return err
	}

	if _, ok := secrets.Certs["k8sserviceaccount"]; !ok {
		return errors.New("missing certs.k8sserviceaccount")
	}
	serviceAccountKeyPEM := decode(secrets.Certs["k8sserviceaccount"].Key)
	serviceAccountKeyBlock, _ := pem.Decode(serviceAccountKeyPEM)
	if serviceAccountKeyBlock == nil {
		return errors.New("decode service account key: no PEM block")
	}
	serviceAccountKey, err := parsePrivateKey(serviceAccountKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse service account key: %w", err)
	}
	serviceAccountPEM, err := marshalPrivateKey(serviceAccountKey)
	if err != nil {
		return fmt.Errorf("marshal service account key: %w", err)
	}
	writeSecret(filepath.Join(output, "sa.key"), serviceAccountPEM, 0o600)
	serviceAccountPublicPEM, err := marshalPublicKey(serviceAccountKey)
	if err != nil {
		return fmt.Errorf("marshal service account public key: %w", err)
	}
	writeSecret(filepath.Join(output, "sa.pub"), serviceAccountPublicPEM, 0o644)

	requests := []certificateRequest{
		{
			Name: "apiserver", CommonName: "kube-apiserver",
			DNSNames:    apiserverDNS,
			IPAddresses: apiserverIPs,
			Usages:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{Name: "apiserver-kubelet-client", CommonName: "kube-apiserver-kubelet-client", Organizations: []string{"system:masters"}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{Name: "front-proxy-client", CommonName: "front-proxy-client", Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{Name: "etcd/server", CommonName: "kine", DNSNames: []string{"kine", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{Name: "apiserver-etcd-client", CommonName: "kube-apiserver-etcd-client", Organizations: []string{"system:masters"}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{Name: "controller-manager", CommonName: "system:kube-controller-manager", Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{Name: "scheduler", CommonName: "system:kube-scheduler", Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{Name: "admin", CommonName: "kubernetes-admin", Organizations: []string{"system:masters"}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
	}
	for _, request := range requests {
		caPrefix := kubernetesCA
		if request.Name == "front-proxy-client" {
			caPrefix = frontProxyCA
		} else if request.Name == "etcd/server" || request.Name == "apiserver-etcd-client" {
			caPrefix = etcdCA
		}
		if err := issueCertificate(filepath.Join(output, request.Name), caPrefix, request); err != nil {
			return err
		}
	}

	kubeconfigs := []kubeconfigRequest{
		{Name: "admin.conf", Certificate: "admin.crt", Key: "admin.key", Server: options.APIServerURL, User: "kubernetes-admin"},
		{Name: "controller-manager.conf", Certificate: "controller-manager.crt", Key: "controller-manager.key", Server: "https://kube-apiserver:6443", User: "system:kube-controller-manager"},
		{Name: "scheduler.conf", Certificate: "scheduler.crt", Key: "scheduler.key", Server: "https://kube-apiserver:6443", User: "system:kube-scheduler"},
	}
	for _, config := range kubeconfigs {
		contents, err := kubeconfig(kubernetesCA+".crt", filepath.Join(output, config.Certificate), filepath.Join(output, config.Key), config.Server, config.User, clusterName)
		if err != nil {
			return err
		}
		writeSecret(filepath.Join(output, "kubeconfig", config.Name), contents, 0o600)
	}

	encryptionKey := decode(secrets.Secrets.SecretboxEncryptionSecret)
	if len(encryptionKey) != 32 {
		return errors.New("secretbox encryption key must decode to 32 bytes")
	}
	encryptionConfig := fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - secretbox:
      keys:
      - name: talos-derived-key
        secret: %s
  - identity: {}
`, secrets.Secrets.SecretboxEncryptionSecret)
	writeSecret(filepath.Join(output, "encryption-config.yaml"), []byte(encryptionConfig), 0o600)

	fmt.Printf("PKI generated in %s/\n", output)
	fmt.Printf("kubectl: KUBECONFIG=%s/kubeconfig/admin.conf kubectl get --raw=/readyz\n", output)
	return nil
}

func issueCertificate(outputPrefix, caPrefix string, request certificateRequest) error {
	caCertificate, caPrivateKey, err := readCAPair(caPrefix+".crt", caPrefix+".key")
	if err != nil {
		return fmt.Errorf("read CA for %s: %w", request.Name, err)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key for %s: %w", request.Name, err)
	}
	now := time.Now()
	notAfter := now.Add(365 * 24 * time.Hour)
	if caCertificate.NotAfter.Before(notAfter) {
		notAfter = caCertificate.NotAfter.Add(-time.Minute)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   request.CommonName,
			Organization: request.Organizations,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           request.Usages,
		BasicConstraintsValid: true,
		DNSNames:              request.DNSNames,
		IPAddresses:           request.IPAddresses,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return fmt.Errorf("sign certificate for %s: %w", request.Name, err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM, err := marshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal key for %s: %w", request.Name, err)
	}
	if err := os.WriteFile(outputPrefix+".crt", certificatePEM, 0o644); err != nil {
		return fmt.Errorf("write certificate for %s: %w", request.Name, err)
	}
	if err := os.WriteFile(outputPrefix+".key", privateKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write key for %s: %w", request.Name, err)
	}
	return nil
}

func issueTalosServerCertificate(caCertificatePath, caKeyPath, certificatePath, keyPath, sansCSV string) error {
	caCertificate, caPrivateKey, err := readCAPair(caCertificatePath, caKeyPath)
	if err != nil {
		return fmt.Errorf("read Talos CA: %w", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate Talos server key: %w", err)
	}
	now := time.Now()
	notAfter := now.Add(365 * 24 * time.Hour)
	if caCertificate.NotAfter.Before(notAfter) {
		notAfter = caCertificate.NotAfter.Add(-time.Minute)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "talos-csr-signer"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, san := range strings.Split(sansCSV, ",") {
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
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, caCertificate, publicKey, caPrivateKey)
	if err != nil {
		return fmt.Errorf("sign Talos server certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return fmt.Errorf("parse generated Talos server certificate: %w", err)
	}
	if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
		return fmt.Errorf("verify generated Talos server certificate: %w", err)
	}
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o644); err != nil {
		return fmt.Errorf("write Talos server certificate: %w", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal Talos server key: %w", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), 0o600); err != nil {
		return fmt.Errorf("write Talos server key: %w", err)
	}
	return nil
}

func readCAPair(certificatePath, keyPath string) (*x509.Certificate, any, error) {
	certificate, err := readCertificate(certificatePath)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := parsePrivateKey(readPEM(keyPath))
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	return certificate, privateKey, nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, fmt.Errorf("decode certificate %s: no PEM block", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	return certificate, nil
}

func readPEM(path string) []byte {
	contents, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Errorf("read %s: %w", path, err))
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		panic(fmt.Errorf("decode %s: no PEM block", path))
	}
	return block.Bytes
}

func parsePrivateKey(der []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key format")
}

func marshalPrivateKey(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func marshalPublicKey(key any) ([]byte, error) {
	var der []byte
	var err error
	switch key := key.(type) {
	case *rsa.PrivateKey:
		der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	case *ecdsa.PrivateKey:
		der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	default:
		return nil, fmt.Errorf("unsupported service account key type: %T", key)
	}
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func randomSerial() *big.Int {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		panic(fmt.Errorf("generate certificate serial number: %w", err))
	}
	return serial
}

func kubeconfig(caPath, certificatePath, keyPath, server, user, clusterName string) ([]byte, error) {
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	contents := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %s
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: %s
  user:
    client-certificate-data: %s
    client-key-data: %s
contexts:
- name: %s@%s
  context:
    cluster: %s
    user: %s
current-context: %s@%s
`,
		clusterName,
		server,
		base64.StdEncoding.EncodeToString(ca),
		user,
		base64.StdEncoding.EncodeToString(certificate),
		base64.StdEncoding.EncodeToString(key),
		user,
		clusterName,
		clusterName,
		user,
		user,
		clusterName,
	)
	return []byte(contents), nil
}

func parseSANS(csv string) ([]string, []net.IP, error) {
	var dnsNames []string
	var ipAddresses []net.IP
	for _, value := range strings.Split(csv, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if ip := net.ParseIP(value); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, value)
		}
	}
	return dnsNames, ipAddresses, nil
}

func validateAPIServerURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("parse --api-server-url: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("--api-server-url must be an https URL with a host, for example https://127.0.0.1:6443")
	}
	return nil
}
