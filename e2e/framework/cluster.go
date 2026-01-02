// Package framework provides utilities for end-to-end testing of the EKS Pod Identity Webhook.
// It includes helpers for Kind cluster lifecycle management, Kubernetes client setup,
// and test resource management.
package framework

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
)

const (
	// KindClusterName is the default name for the Kind cluster used in e2e tests.
	KindClusterName = "eks-webhook-e2e"

	// KindNodeImage is the Kind node image version used for testing.
	KindNodeImage = "kindest/node:v1.31.0"

	// WebhookNamespace is the namespace where the webhook is deployed.
	WebhookNamespace = "aws-pod-identity-webhook"

	// WebhookImageName is the Docker image name for the webhook in e2e tests.
	WebhookImageName = "eks-pod-identity-webhook:e2e-test"

	// defaultClusterWaitTimeout is the default timeout for waiting for the cluster to be ready.
	defaultClusterWaitTimeout = 5 * time.Minute

	// tempKubeconfigPrefix is the prefix used for temporary kubeconfig directories.
	tempKubeconfigPrefix = "kind-kubeconfig-"
)

// ClusterConfig holds the configuration for a Kind cluster.
type ClusterConfig struct {
	// Name is the name of the Kind cluster.
	Name string

	// NodeImage is the Docker image to use for Kind nodes.
	NodeImage string

	// Retain keeps the cluster running after tests complete (useful for debugging).
	Retain bool

	// KubeConfig is the path to the kubeconfig file. If empty, a temporary file is created.
	KubeConfig string
}

// applyDefaults sets default values for empty fields in ClusterConfig.
func (cfg *ClusterConfig) applyDefaults() {
	if cfg.Name == "" {
		cfg.Name = KindClusterName
	}
	if cfg.NodeImage == "" {
		cfg.NodeImage = KindNodeImage
	}
}

// clusterExists checks if a Kind cluster with the given name already exists.
func clusterExists(provider *cluster.Provider, name string) (bool, error) {
	clusters, err := provider.List()
	if err != nil {
		return false, fmt.Errorf("failed to list Kind clusters: %w", err)
	}
	for _, c := range clusters {
		if c == name {
			return true, nil
		}
	}
	return false, nil
}

// createKubeconfigPath creates a temporary kubeconfig file path if not specified.
func createKubeconfigPath(cfg *ClusterConfig) (string, error) {
	if cfg.KubeConfig != "" {
		return cfg.KubeConfig, nil
	}

	tmpDir, err := os.MkdirTemp("", tempKubeconfigPrefix+"*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory for kubeconfig: %w", err)
	}
	kubeconfigPath := filepath.Join(tmpDir, "kubeconfig")
	cfg.KubeConfig = kubeconfigPath
	return kubeconfigPath, nil
}

// getWaitTimeout extracts the wait timeout from context deadline or returns default.
func getWaitTimeout(ctx context.Context) (time.Duration, error) {
	if deadline, ok := ctx.Deadline(); ok {
		waitTimeout := time.Until(deadline)
		if waitTimeout <= 0 {
			return 0, errors.New("context deadline already exceeded")
		}
		return waitTimeout, nil
	}
	return defaultClusterWaitTimeout, nil
}

// CreateKindCluster creates a new Kind cluster with the provided configuration
// and returns a rest.Config for connecting to it.
func CreateKindCluster(ctx context.Context, cfg *ClusterConfig) (*rest.Config, error) {
	if cfg == nil {
		cfg = &ClusterConfig{}
	}
	cfg.applyDefaults()

	provider := cluster.NewProvider()

	exists, err := clusterExists(provider, cfg.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("cluster %q already exists", cfg.Name)
	}

	kubeconfigPath, err := createKubeconfigPath(cfg)
	if err != nil {
		return nil, err
	}

	waitTimeout, err := getWaitTimeout(ctx)
	if err != nil {
		return nil, err
	}

	createOpts := []cluster.CreateOption{
		cluster.CreateWithNodeImage(cfg.NodeImage),
		cluster.CreateWithWaitForReady(waitTimeout),
		cluster.CreateWithRetain(cfg.Retain),
	}

	if err := provider.Create(cfg.Name, createOpts...); err != nil {
		return nil, fmt.Errorf("failed to create Kind cluster: %w", err)
	}

	restConfig, err := exportAndLoadKubeconfig(provider, cfg.Name, kubeconfigPath)
	if err != nil {
		if deleteErr := provider.Delete(cfg.Name, ""); deleteErr != nil {
			return nil, fmt.Errorf("%w (also failed to cleanup cluster: %w)", err, deleteErr)
		}
		return nil, err
	}

	return restConfig, nil
}

// exportAndLoadKubeconfig exports kubeconfig from Kind and loads it as rest.Config.
func exportAndLoadKubeconfig(provider *cluster.Provider, clusterName, kubeconfigPath string) (*rest.Config, error) {
	if err := provider.ExportKubeConfig(clusterName, kubeconfigPath, false); err != nil {
		return nil, fmt.Errorf("failed to export kubeconfig: %w", err)
	}

	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build rest config: %w", err)
	}

	return restConfig, nil
}

// DeleteKindCluster deletes the Kind cluster specified in the configuration.
func DeleteKindCluster(cfg *ClusterConfig) error {
	if cfg == nil {
		return errors.New("cluster config is nil")
	}

	if cfg.Name == "" {
		cfg.Name = KindClusterName
	}

	provider := cluster.NewProvider()

	if err := provider.Delete(cfg.Name, cfg.KubeConfig); err != nil {
		return fmt.Errorf("failed to delete Kind cluster %q: %w", cfg.Name, err)
	}

	cleanupTempKubeconfig(cfg.KubeConfig)

	return nil
}

// cleanupTempKubeconfig removes the temporary kubeconfig directory if it matches our pattern.
func cleanupTempKubeconfig(kubeconfigPath string) {
	if kubeconfigPath == "" {
		return
	}

	dir := filepath.Dir(kubeconfigPath)
	base := filepath.Base(dir)

	// Only clean up directories that match our temp kubeconfig pattern.
	// Cleanup is best-effort; failure to remove temp files is not critical.
	if strings.HasPrefix(base, tempKubeconfigPrefix) {
		_ = os.RemoveAll(dir) //nolint:errcheck // Best-effort cleanup of temp files
	}
}

// LoadImageToKind loads a Docker image into the Kind cluster using the Go API.
// It saves the image to a tar archive and loads it into all cluster nodes.
func LoadImageToKind(clusterName, imageName string) error {
	if clusterName == "" {
		clusterName = KindClusterName
	}

	if imageName == "" {
		return errors.New("image name cannot be empty")
	}

	provider := cluster.NewProvider()

	// Get all internal nodes (excludes load balancer)
	nodeList, err := provider.ListInternalNodes(clusterName)
	if err != nil {
		return fmt.Errorf("failed to list nodes for cluster %q: %w", clusterName, err)
	}

	if len(nodeList) == 0 {
		return fmt.Errorf("no nodes found in cluster %q", clusterName)
	}

	// Save docker image to a temporary tar file
	tmpFile, err := os.CreateTemp("", "kind-image-*.tar")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close() //nolint:errcheck // Best-effort close before docker save overwrites
	defer func() {
		_ = os.Remove(tmpPath) //nolint:errcheck // Best-effort cleanup of temp file
	}()

	// Use docker save to export the image
	// #nosec G204 -- imageName is controlled by test code, not user input
	saveCmd := exec.Command("docker", "save", "-o", tmpPath, imageName)
	saveCmd.Stderr = os.Stderr
	if err := saveCmd.Run(); err != nil {
		return fmt.Errorf("failed to save docker image %q: %w", imageName, err)
	}

	// Load the image into each node
	for _, node := range nodeList {
		// #nosec G304 -- tmpPath is created by os.CreateTemp, not user input
		f, err := os.Open(tmpPath)
		if err != nil {
			return fmt.Errorf("failed to open image archive: %w", err)
		}

		err = nodeutils.LoadImageArchive(node, f)
		_ = f.Close() //nolint:errcheck // Best-effort close after loading
		if err != nil {
			return fmt.Errorf("failed to load image into node %s: %w", node.String(), err)
		}
	}

	return nil
}
