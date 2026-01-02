// Package framework provides utilities for end-to-end testing of the webhook.
package framework

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const (
	helmRepoName          = "mondu-helm-charts"
	helmRepoURL           = "https://mondu-ai.github.io/helm-charts-community"
	helmChartName         = "eks-pod-identity-webhook"
	helmReleaseName       = "eks-pod-identity-webhook"
	helmTLSSecretName     = "e2e-webhook-tls-secret"
	helmDeploymentName    = "eks-pod-identity-webhook-deployment"
	helmWebhookConfigName = "eks-pod-identity-webhook-cfg"

	// HelmServiceName is the service name created by the Helm chart.
	HelmServiceName = "eks-pod-identity-webhook-svc"

	helmDeploymentReadyTimeout = 2 * time.Minute
	helmDeploymentPollInterval = 2 * time.Second

	// Kubernetes label keys and values for resource identification
	appLabelKey   = "app.kubernetes.io/name"
	appLabelValue = "aws-pod-identity-webhook"
)

// HelmDeployer handles deployment of the webhook via Helm.
type HelmDeployer struct {
	client       kubernetes.Interface
	namespace    string
	awsRegion    string
	certificates *WebhookCertificates
}

// NewHelmDeployer creates a new HelmDeployer with the provided configuration.
func NewHelmDeployer(client kubernetes.Interface, certs *WebhookCertificates, awsRegion string) *HelmDeployer {
	return &HelmDeployer{
		client:       client,
		namespace:    WebhookNamespace,
		awsRegion:    awsRegion,
		certificates: certs,
	}
}

// Deploy deploys the webhook using Helm and patches the CA bundle.
func (d *HelmDeployer) Deploy(ctx context.Context) error {
	if err := d.createNamespace(ctx); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Create TLS secret before helm install (chart expects it to exist)
	if err := d.createTLSSecret(ctx); err != nil {
		return fmt.Errorf("failed to create TLS secret: %w", err)
	}

	if err := d.addHelmRepo(ctx); err != nil {
		return fmt.Errorf("failed to add helm repo: %w", err)
	}

	if err := d.installChart(ctx); err != nil {
		return fmt.Errorf("failed to install helm chart: %w", err)
	}

	if err := d.waitForDeploymentReady(ctx); err != nil {
		return fmt.Errorf("failed waiting for deployment to be ready: %w", err)
	}

	// Patch MutatingWebhookConfiguration with CA bundle
	// (chart uses cert-manager annotation which won't work without cert-manager)
	if err := d.patchWebhookCABundle(ctx); err != nil {
		return fmt.Errorf("failed to patch webhook CA bundle: %w", err)
	}

	return nil
}

// Cleanup removes the Helm release and associated resources.
func (d *HelmDeployer) Cleanup(ctx context.Context) error {
	var errs []error

	// Uninstall helm release (ignore errors if release doesn't exist)
	// #nosec G204 -- arguments are constants, not user input
	cmd := exec.CommandContext(ctx, "helm", "uninstall", helmReleaseName,
		"--namespace", d.namespace)
	_, _ = cmd.CombinedOutput() //nolint:errcheck // Intentionally ignoring errors

	if err := d.client.CoreV1().Namespaces().Delete(
		ctx, d.namespace, metav1.DeleteOptions{},
	); err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete namespace: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}

	return nil
}

func (d *HelmDeployer) createNamespace(ctx context.Context) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: d.namespace,
			Labels: map[string]string{
				appLabelKey: appLabelValue,
			},
		},
	}

	_, err := d.client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func (d *HelmDeployer) createTLSSecret(ctx context.Context) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      helmTLSSecretName,
			Namespace: d.namespace,
			Labels: map[string]string{
				appLabelKey: appLabelValue,
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       d.certificates.ServerCert,
			corev1.TLSPrivateKeyKey: d.certificates.ServerKey,
		},
	}

	_, err := d.client.CoreV1().Secrets(d.namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func (d *HelmDeployer) addHelmRepo(ctx context.Context) error {
	// Add helm repo
	cmd := exec.CommandContext(ctx, "helm", "repo", "add", helmRepoName, helmRepoURL)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("helm repo add failed: %w: %s", err, out)
	}

	// Update repo
	cmd = exec.CommandContext(ctx, "helm", "repo", "update")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("helm repo update failed: %w: %s", err, out)
	}

	return nil
}

func (d *HelmDeployer) installChart(ctx context.Context) error {
	// #nosec G204 -- arguments are constants, not user input
	cmd := exec.CommandContext(ctx, "helm", "install",
		helmReleaseName,
		fmt.Sprintf("%s/%s", helmRepoName, helmChartName),
		"--namespace", d.namespace,
		"--set", "image.repository=eks-pod-identity-webhook",
		"--set", "image.tag=e2e-test",
		"--set", "image.pullPolicy=Never",
		"--set", "replicaCount=1",
		"--set", "certManager.enabled=false",
		"--set", fmt.Sprintf("existingTLSSecret=%s", helmTLSSecretName),
		"--set", "nodeSelector=null",
		"--set", fmt.Sprintf("env.AWS_REGION=%s", d.awsRegion),
		"--set", "env.GIN_MODE=release",
		"--wait",
		"--timeout", "2m",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("helm install failed: %w: %s", err, out)
	}

	return nil
}

func (d *HelmDeployer) waitForDeploymentReady(ctx context.Context) error {
	return wait.PollUntilContextTimeout(ctx, helmDeploymentPollInterval, helmDeploymentReadyTimeout, true,
		func(ctx context.Context) (bool, error) {
			deployment, err := d.client.AppsV1().Deployments(d.namespace).Get(ctx, helmDeploymentName, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}

			if deployment.Status.ReadyReplicas >= 1 && deployment.Status.AvailableReplicas >= 1 {
				return true, nil
			}

			return false, nil
		},
	)
}

func (d *HelmDeployer) patchWebhookCABundle(ctx context.Context) error {
	// Get the existing MutatingWebhookConfiguration
	webhookConfig, err := d.client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(
		ctx, helmWebhookConfigName, metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to get webhook configuration: %w", err)
	}

	// Patch each webhook with the CA bundle
	for i := range webhookConfig.Webhooks {
		webhookConfig.Webhooks[i].ClientConfig.CABundle = d.certificates.CACert
	}

	_, err = d.client.AdmissionregistrationV1().MutatingWebhookConfigurations().Update(
		ctx, webhookConfig, metav1.UpdateOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to update webhook configuration: %w", err)
	}

	return nil
}
