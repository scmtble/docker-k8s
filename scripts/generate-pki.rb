#!/usr/bin/env ruby

require "base64"
require "fileutils"
require "ipaddr"
require "openssl"
require "securerandom"
require "tmpdir"
require "yaml"

SOURCE = ARGV.fetch(0, "secrets.yaml")
OUT = ARGV.fetch(1, "pki")
File.umask(0o077)

abort "refusing to overwrite existing directory: #{OUT}" if File.exist?(OUT)

secrets = YAML.safe_load(File.read(SOURCE), permitted_classes: [], aliases: false)
certs = secrets.fetch("certs")

FileUtils.mkdir_p(File.join(OUT, "etcd"), mode: 0o700)
FileUtils.mkdir_p(File.join(OUT, "kubeconfig"), mode: 0o700)
FileUtils.mkdir_p(File.join(OUT, "talos"), mode: 0o700)

def decoded(value)
  Base64.strict_decode64(value)
rescue ArgumentError
  abort "invalid base64 value in secrets file"
end

def write_secret(path, contents, mode = 0o600)
  File.binwrite(path, contents)
  File.chmod(mode, path)
end

def import_pair(source, destination, certs)
  pair = certs.fetch(source)
  write_secret("#{destination}.crt", decoded(pair.fetch("crt")), 0o644)
  write_secret("#{destination}.key", decoded(pair.fetch("key")))
end

import_pair("k8s", File.join(OUT, "ca"), certs)
import_pair("k8saggregator", File.join(OUT, "front-proxy-ca"), certs)
import_pair("etcd", File.join(OUT, "etcd", "ca"), certs)

talos_pair = certs.fetch("os")
write_secret(File.join(OUT, "talos", "ca.crt"), decoded(talos_pair.fetch("crt")), 0o644)
talos_ca_key = decoded(talos_pair.fetch("key"))
  .gsub("BEGIN ED25519 PRIVATE KEY", "BEGIN PRIVATE KEY")
  .gsub("END ED25519 PRIVATE KEY", "END PRIVATE KEY")
write_secret(File.join(OUT, "talos", "ca.key"), talos_ca_key)
talos_token = secrets.fetch("trustdinfo").fetch("token")
write_secret(File.join(OUT, "talos", "signer.env"), "TALOS_TOKEN=#{talos_token}\n")

talos_sans = ENV.fetch("TALOS_SIGNER_SANS", "talos-csr-signer,localhost,127.0.0.1")
helper = File.expand_path("generate-talos-server-cert.go", __dir__)
generated = system(
  {"GOCACHE" => File.join(Dir.tmpdir, "docker-k8s-go-cache")},
  "go", "run", helper,
  File.join(OUT, "talos", "ca.crt"),
  File.join(OUT, "talos", "ca.key"),
  File.join(OUT, "talos", "server.crt"),
  File.join(OUT, "talos", "server.key"),
  talos_sans,
  out: File::NULL,
)
abort "failed to generate Talos CSR signer certificate" unless generated

sa_key = decoded(certs.fetch("k8sserviceaccount").fetch("key"))
write_secret(File.join(OUT, "sa.key"), sa_key)
sa = OpenSSL::PKey.read(sa_key)
write_secret(File.join(OUT, "sa.pub"), sa.public_key.to_pem, 0o644)

def issue(out, name, ca_prefix, cn:, organizations: [], dns: [], ips: [], usages: %w[clientAuth serverAuth])
  ca_cert = OpenSSL::X509::Certificate.new(File.binread("#{ca_prefix}.crt"))
  ca_key = OpenSSL::PKey.read(File.binread("#{ca_prefix}.key"))
  key = OpenSSL::PKey::EC.generate("prime256v1")

  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = SecureRandom.random_number(2**128)
  cert.subject = OpenSSL::X509::Name.new([["CN", cn], *organizations.map { |org| ["O", org] }])
  cert.issuer = ca_cert.subject
  cert.public_key = key
  cert.not_before = Time.now - 300
  cert.not_after = [Time.now + (365 * 24 * 60 * 60), ca_cert.not_after - 60].min

  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = cert
  factory.issuer_certificate = ca_cert
  cert.add_extension(factory.create_extension("basicConstraints", "CA:FALSE", true))
  cert.add_extension(factory.create_extension("keyUsage", "digitalSignature,keyEncipherment", true))
  cert.add_extension(factory.create_extension("extendedKeyUsage", usages.join(","))) unless usages.empty?
  sans = dns.map { |value| "DNS:#{value}" } + ips.map { |value| "IP:#{IPAddr.new(value)}" }
  cert.add_extension(factory.create_extension("subjectAltName", sans.join(","))) unless sans.empty?
  cert.add_extension(factory.create_extension("subjectKeyIdentifier", "hash"))
  cert.add_extension(factory.create_extension("authorityKeyIdentifier", "keyid:always"))
  cert.sign(ca_key, OpenSSL::Digest::SHA256.new)

  prefix = File.join(out, name)
  write_secret("#{prefix}.crt", cert.to_pem, 0o644)
  write_secret("#{prefix}.key", key.to_pem)
end

k8s_ca = File.join(OUT, "ca")
etcd_ca = File.join(OUT, "etcd", "ca")
proxy_ca = File.join(OUT, "front-proxy-ca")

issue(OUT, "apiserver", k8s_ca,
  cn: "kube-apiserver",
  dns: %w[kubernetes kubernetes.default kubernetes.default.svc kubernetes.default.svc.cluster.local kube-apiserver localhost],
  ips: %w[10.96.0.1 127.0.0.1], usages: %w[serverAuth])
issue(OUT, "apiserver-kubelet-client", k8s_ca,
  cn: "kube-apiserver-kubelet-client", organizations: ["system:masters"], usages: %w[clientAuth])
issue(OUT, "front-proxy-client", proxy_ca,
  cn: "front-proxy-client", usages: %w[clientAuth])
issue(File.join(OUT, "etcd"), "server", etcd_ca,
  cn: "kine", dns: %w[kine localhost], ips: %w[127.0.0.1], usages: %w[serverAuth])
issue(OUT, "apiserver-etcd-client", etcd_ca,
  cn: "kube-apiserver-etcd-client", organizations: ["system:masters"], usages: %w[clientAuth])
issue(OUT, "controller-manager", k8s_ca,
  cn: "system:kube-controller-manager", usages: %w[clientAuth])
issue(OUT, "scheduler", k8s_ca,
  cn: "system:kube-scheduler", usages: %w[clientAuth])
issue(OUT, "admin", k8s_ca,
  cn: "kubernetes-admin", organizations: ["system:masters"], usages: %w[clientAuth])

def kubeconfig(ca, cert, key, server, user)
  <<~YAML
    apiVersion: v1
    kind: Config
    clusters:
    - name: compose-k8s
      cluster:
        server: #{server}
        certificate-authority-data: #{Base64.strict_encode64(File.binread(ca))}
    users:
    - name: #{user}
      user:
        client-certificate-data: #{Base64.strict_encode64(File.binread(cert))}
        client-key-data: #{Base64.strict_encode64(File.binread(key))}
    contexts:
    - name: #{user}@compose-k8s
      context:
        cluster: compose-k8s
        user: #{user}
    current-context: #{user}@compose-k8s
  YAML
end

write_secret(File.join(OUT, "kubeconfig", "admin.conf"),
  kubeconfig("#{k8s_ca}.crt", File.join(OUT, "admin.crt"), File.join(OUT, "admin.key"), "https://127.0.0.1:6443", "kubernetes-admin"))
write_secret(File.join(OUT, "kubeconfig", "controller-manager.conf"),
  kubeconfig("#{k8s_ca}.crt", File.join(OUT, "controller-manager.crt"), File.join(OUT, "controller-manager.key"), "https://kube-apiserver:6443", "system:kube-controller-manager"))
write_secret(File.join(OUT, "kubeconfig", "scheduler.conf"),
  kubeconfig("#{k8s_ca}.crt", File.join(OUT, "scheduler.crt"), File.join(OUT, "scheduler.key"), "https://kube-apiserver:6443", "system:kube-scheduler"))

encryption_key = secrets.fetch("secrets").fetch("secretboxencryptionsecret")
abort "secretbox encryption key must decode to 32 bytes" unless decoded(encryption_key).bytesize == 32
write_secret(File.join(OUT, "encryption-config.yaml"), <<~YAML)
  apiVersion: apiserver.config.k8s.io/v1
  kind: EncryptionConfiguration
  resources:
  - resources:
    - secrets
    providers:
    - secretbox:
        keys:
        - name: talos-derived-key
          secret: #{encryption_key}
    - identity: {}
YAML

puts "PKI generated in #{OUT}/"
puts "kubectl: KUBECONFIG=#{OUT}/kubeconfig/admin.conf kubectl get --raw=/readyz"
