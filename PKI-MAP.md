# Talos secrets 到 Kubernetes PKI 的映射

图中的实线表示直接引用或解码写出，虚线表示使用 CA 签发新证书。
所有源字段都来自 `secrets.yaml`，图中只展示字段名，不展示字段内容。

```mermaid
flowchart LR
  subgraph S["Talos secrets.yaml"]
    K8S_CRT["certs.k8s.crt"]
    K8S_KEY["certs.k8s.key"]
    AGG_CRT["certs.k8saggregator.crt"]
    AGG_KEY["certs.k8saggregator.key"]
    ETCD_CRT["certs.etcd.crt"]
    ETCD_KEY["certs.etcd.key"]
    SA_KEY["certs.k8sserviceaccount.key"]
    ENC_KEY["secrets.secretboxencryptionsecret"]
    OS_CRT["certs.os.crt"]
    OS_KEY["certs.os.key"]
    TRUST_TOKEN["trustdinfo.token"]
  end

  subgraph ROOTS["直接引用的根材料"]
    K8S_CA["pki/ca.crt + ca.key<br/>Kubernetes CA"]
    PROXY_CA["pki/front-proxy-ca.crt + .key<br/>Aggregator CA"]
    ETCD_CA["pki/etcd/ca.crt + ca.key<br/>etcd CA"]
    SA_PRIVATE["pki/sa.key<br/>ServiceAccount 签名私钥"]
    SA_PUBLIC["pki/sa.pub<br/>从 sa.key 导出"]
    ENC["pki/encryption-config.yaml<br/>SecretBox 静态数据加密"]
    TALOS_CA["pki/talos/ca.crt + ca.key<br/>Talos Machine CA"]
    TALOS_TOKEN["pki/talos/signer.env<br/>Signer 共享认证 token"]
  end

  K8S_CRT --> K8S_CA
  K8S_KEY --> K8S_CA
  AGG_CRT --> PROXY_CA
  AGG_KEY --> PROXY_CA
  ETCD_CRT --> ETCD_CA
  ETCD_KEY --> ETCD_CA
  SA_KEY --> SA_PRIVATE --> SA_PUBLIC
  ENC_KEY --> ENC
  OS_CRT --> TALOS_CA
  OS_KEY --> TALOS_CA
  TRUST_TOKEN --> TALOS_TOKEN

  subgraph K8S_LEAF["Kubernetes CA 签发"]
    API["apiserver.crt/.key<br/>serverAuth"]
    KUBELET_CLIENT["apiserver-kubelet-client.crt/.key<br/>clientAuth · O=system:masters"]
    CM["controller-manager.crt/.key<br/>clientAuth"]
    SCHED["scheduler.crt/.key<br/>clientAuth"]
    ADMIN["admin.crt/.key<br/>clientAuth · O=system:masters"]
  end

  K8S_CA -. "签发" .-> API
  K8S_CA -. "签发" .-> KUBELET_CLIENT
  K8S_CA -. "签发" .-> CM
  K8S_CA -. "签发" .-> SCHED
  K8S_CA -. "签发" .-> ADMIN

  subgraph PROXY_LEAF["Aggregator CA 签发"]
    PROXY_CLIENT["front-proxy-client.crt/.key<br/>clientAuth"]
  end
  PROXY_CA -. "签发" .-> PROXY_CLIENT

  subgraph ETCD_LEAF["etcd CA 签发，用于 Kine mTLS"]
    KINE_SERVER["etcd/server.crt/.key<br/>serverAuth · SAN DNS:kine"]
    API_ETCD["apiserver-etcd-client.crt/.key<br/>clientAuth"]
  end
  ETCD_CA -. "签发" .-> KINE_SERVER
  ETCD_CA -. "签发" .-> API_ETCD

  subgraph TALOS_LEAF["Talos Machine CA 签发"]
    TALOS_SERVER["talos/server.crt/.key<br/>talos-csr-signer serverAuth"]
    TALOS_WORKER["Talos Worker apid 证书<br/>运行时按 CSR 签发"]
  end
  TALOS_CA -. "生成时签发" .-> TALOS_SERVER
  TALOS_CA -. "运行时签发" .-> TALOS_WORKER
  TALOS_TOKEN --> TALOS_WORKER

  subgraph KCFG["嵌入证书生成 kubeconfig"]
    ADMIN_CONF["kubeconfig/admin.conf<br/>127.0.0.1:6443"]
    CM_CONF["kubeconfig/controller-manager.conf"]
    SCHED_CONF["kubeconfig/scheduler.conf"]
  end
  K8S_CA --> ADMIN_CONF
  ADMIN --> ADMIN_CONF
  K8S_CA --> CM_CONF
  CM --> CM_CONF
  K8S_CA --> SCHED_CONF
  SCHED --> SCHED_CONF
```

## 字段和用途

| `secrets.yaml` 源字段 | 输出或派生内容 | 使用者 |
|---|---|---|
| `certs.k8s.crt`、`certs.k8s.key` | Kubernetes CA；签发 API Server、控制器、调度器和管理员证书 | kube-apiserver、controller-manager、scheduler、kubectl |
| `certs.k8saggregator.crt`、`certs.k8saggregator.key` | front-proxy CA；签发 `front-proxy-client` | kube-apiserver aggregation layer |
| `certs.etcd.crt`、`certs.etcd.key` | etcd CA；签发 Kine server 和 API Server client 证书 | Kine 与 kube-apiserver 之间的 mTLS |
| `certs.k8sserviceaccount.key` | 直接写成 `sa.key`，并导出 `sa.pub` | API Server 验证、controller-manager 签发 ServiceAccount token |
| `secrets.secretboxencryptionsecret` | 写入 `encryption-config.yaml` 的 SecretBox provider | kube-apiserver 加密存入 Kine/PostgreSQL 的 Kubernetes Secret |
| `certs.os.crt`、`certs.os.key` | Talos Machine CA；签发 signer 服务端证书及 Worker apid 证书 | talos-csr-signer、Talos Worker |
| `trustdinfo.token` | 写入私有 `signer.env` | Worker 请求 Talos Machine 证书时的共享认证 |

## 当前没有使用的 Talos 字段

下面这些材料属于 Talos OS、节点信任或 bootstrap 流程，不参与这个 Docker
Compose Kubernetes 控制平面：

- `cluster.id`、`cluster.secret`
- `secrets.bootstraptoken`

## mTLS 数据流

```mermaid
sequenceDiagram
  participant A as kube-apiserver
  participant K as Kine
  participant P as PostgreSQL

  A->>K: TLS client cert: apiserver-etcd-client.crt
  K-->>A: TLS server cert: etcd/server.crt (SAN: kine)
  Note over A,K: 双方都使用 pki/etcd/ca.crt 验证对端
  K->>P: PostgreSQL connection from KINE_ENDPOINT
  Note over K,P: PostgreSQL TLS 独立于 etcd CA
```
