package main

import (
	"fmt"
	"os"

	"docker-k8s/internal/pki"
)

const usage = `Usage: pki <command> [flags]

Commands:
  generate   Generate a Kubernetes control-plane PKI from Talos secrets

Run "pki <command> -h" for command-specific flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	command := os.Args[1]
	switch command {
	case "generate":
		if err := runGenerate(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "pki generate: %v\n", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "pki: unknown command %q\n\n%s", command, usage)
		os.Exit(2)
	}
}

func runGenerate(args []string) error {
	options := pki.GenerateOptions{
		Source:         "secrets.yaml",
		Output:         "pki",
		TalosSANS:      os.Getenv("TALOS_SIGNER_SANS"),
		KubernetesSANS: os.Getenv("KUBERNETES_SANS"),
		APIServerURL:   os.Getenv("API_SERVER_URL"),
	}

	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "-h", "--help":
			fmt.Print(generateUsage)
			return nil
		case "--source", "-s":
			index++
			if index >= len(args) {
				return fmt.Errorf("%s requires a value", args[index-1])
			}
			options.Source = args[index]
		case "--output", "-o":
			index++
			if index >= len(args) {
				return fmt.Errorf("%s requires a value", args[index-1])
			}
			options.Output = args[index]
		case "--talos-sans":
			index++
			if index >= len(args) {
				return fmt.Errorf("%s requires a value", args[index-1])
			}
			options.TalosSANS = args[index]
		case "--cluster-name":
			index++
			if index >= len(args) {
				return fmt.Errorf("%s requires a value", args[index-1])
			}
			options.ClusterName = args[index]
		case "--api-server-url":
			index++
			if index >= len(args) {
				return fmt.Errorf("%s requires a value", args[index-1])
			}
			options.APIServerURL = args[index]
		case "--kubernetes-sans":
			index++
			if index >= len(args) {
				return fmt.Errorf("%s requires a value", args[index-1])
			}
			options.KubernetesSANS = args[index]
		default:
			return fmt.Errorf("unknown flag or argument %q", args[index])
		}
	}

	return pki.Generate(options)
}

const generateUsage = `Usage: pki generate [flags]

Flags:
  -s, --source string          Talos secrets file (default "secrets.yaml")
  -o, --output string          output PKI directory (default "pki")
      --cluster-name string    required kubeconfig cluster name
      --api-server-url string  required API server URL for admin kubeconfig,
                              for example https://127.0.0.1:6443
      --kubernetes-sans string required comma-separated DNS names and IPs for
                              the kube-apiserver certificate
      --talos-sans string      comma-separated SANs for the Talos CSR signer
                              (default "talos-csr-signer,localhost,127.0.0.1")

The API_SERVER_URL, KUBERNETES_SANS, and TALOS_SIGNER_SANS environment
variables are used when the corresponding flags are not set.
`
