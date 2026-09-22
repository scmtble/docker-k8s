# Kubernetes control plane with Docker Compose

See [PKI-MAP.md](PKI-MAP.md) for the complete mapping from Talos
`secrets.yaml` fields to the generated Kubernetes certificates and kubeconfigs.

This development setup derives Kubernetes component credentials from a Talos
`secrets.yaml` and runs a single-instance control plane. The source secrets file
is never mounted into a container. Kine exposes its etcd-compatible API over
mutual TLS to the API server and persists Kubernetes state in an external
PostgreSQL database.

## Start

```sh
TALOS_SIGNER_SANS="talos-csr-signer,localhost,127.0.0.1,CONTROL_PLANE_IP" \
  ruby scripts/generate-pki.rb secrets.yaml pki
test -f .env || cp .env.example .env # then set KINE_ENDPOINT on first setup
docker compose up -d
KUBECONFIG="$PWD/pki/kubeconfig/admin.conf" kubectl get --raw=/readyz
KUBECONFIG="$PWD/pki/kubeconfig/admin.conf" kubectl get componentstatuses
```

Inspect logs with `docker compose logs -f`. Stop the containers while retaining
Kubernetes state remains in PostgreSQL after `docker compose down`. Database
backup, retention, TLS, and access control are managed on the PostgreSQL side.

The generated `pki/`, `secrets.yaml`, data, and `.env` are gitignored. The
generator refuses to overwrite an existing PKI directory; move or remove it
explicitly before rotating credentials.

## Scope

This starts Kine, kube-apiserver, kube-controller-manager, kube-scheduler, and
the experimental Talos CSR Signer on host port `50001`. It binds to loopback by
default; expose it only on a controlled control-plane address with firewall rules.
The signer image is pinned by digest because the upstream project is experimental.
It is a control-plane laboratory, not a production topology and not a complete
workload cluster: there is no kubelet, CRI runtime integration, kube-proxy, CNI,
or CoreDNS. Add a Linux worker with kubelet/containerd and a CNI if Pods must run.

The API is bound to `127.0.0.1:6443`, so it is not exposed to the LAN. The
Service and Pod CIDRs are `10.96.0.0/12` and `10.244.0.0/16` respectively.
The API server does not force a loopback advertise address; it automatically
selects its non-loopback container address for endpoint reconciliation.
