// Package e2e provides end-to-end tests for the EKS Pod Identity Webhook.
package e2e

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"

	"eks-pod-identity-webhook-e2e/framework"
)

var (
	testClientset kubernetes.Interface
	clusterCfg    *framework.ClusterConfig
	retain        bool
)

func TestMain(m *testing.M) {
	flag.BoolVar(&retain, "retain", false, "Retain the Kind cluster after tests complete for debugging")
	flag.Parse()

	clusterCfg = &framework.ClusterConfig{
		Name:      framework.KindClusterName,
		NodeImage: framework.KindNodeImage,
		Retain:    retain,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)

	if err := createKindCluster(ctx); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "Failed to create Kind cluster: %v\n", err)
		os.Exit(1)
	}

	if err := buildAndLoadImage(ctx); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "Failed to build and load image: %v\n", err)
		teardown()
		os.Exit(1)
	}

	if err := deployWebhook(ctx); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "Failed to deploy webhook: %v\n", err)
		teardown()
		os.Exit(1)
	}

	cancel()

	code := m.Run()

	teardown()
	os.Exit(code)
}

func teardown() {
	if retain {
		fmt.Printf("Retaining cluster for debugging. Kubeconfig: %s\n", clusterCfg.KubeConfig)
		fmt.Printf("To delete the cluster manually, run: kind delete cluster --name %s\n", clusterCfg.Name)
		return
	}

	if err := framework.DeleteKindCluster(clusterCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to delete Kind cluster: %v\n", err)
	}
}

func createKindCluster(ctx context.Context) error {
	restConfig, err := framework.CreateKindCluster(ctx, clusterCfg)
	if err != nil {
		return fmt.Errorf("failed to create Kind cluster: %w", err)
	}

	testClientset, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	return nil
}

func buildAndLoadImage(ctx context.Context) error {
	projectRoot, err := filepath.Abs("..")
	if err != nil {
		return fmt.Errorf("failed to get project root path: %w", err)
	}

	imageName := framework.WebhookImageName

	cmd := exec.CommandContext(ctx, "docker", "build", "-t", imageName, ".")
	cmd.Dir = projectRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build Docker image: %w", err)
	}

	if err := framework.LoadImageToKind(clusterCfg.Name, imageName); err != nil {
		return fmt.Errorf("failed to load image to Kind: %w", err)
	}

	return nil
}

func deployWebhook(ctx context.Context) error {
	certs, err := framework.GenerateWebhookCertificates(framework.WebhookNamespace, framework.HelmServiceName)
	if err != nil {
		return fmt.Errorf("failed to generate webhook certificates: %w", err)
	}

	deployer := framework.NewHelmDeployer(testClientset, certs, "us-east-1")

	if err := deployer.Deploy(ctx); err != nil {
		return fmt.Errorf("failed to deploy webhook: %w", err)
	}

	return nil
}
