// Package e2e contains end-to-end tests for the EKS Pod Identity Webhook.
package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"eks-pod-identity-webhook-e2e/framework"
)

// TestCertificateHotReload tests that the webhook continues to work after
// TLS certificates are rotated without restarting the pod.
func TestCertificateHotReload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Step 1: Verify webhook works with original certificates
	ns1, err := framework.CreateTestNamespace(ctx, testClientset, "test-cert-reload-before")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(ctx, testClientset, ns1)
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns1, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	pod1 := framework.NewPodBuilder(ns1, "before-rotation").
		WithServiceAccount("test-sa").
		WithContainer("main", "busybox:latest").
		Build()

	createdPod1, err := framework.CreatePodAndWait(ctx, testClientset, pod1)
	require.NoError(t, err, "webhook should work with original certs")

	require.Len(t, createdPod1.Spec.Containers, 1)
	assert.True(t, framework.HasEnvVar(&createdPod1.Spec.Containers[0], framework.AWSRoleArnEnv),
		"pod should be mutated before cert rotation")

	// Step 2: Generate new certificates and update the TLS secret + caBundle
	newCerts, err := framework.GenerateWebhookCertificates(framework.WebhookNamespace, framework.HelmServiceName)
	require.NoError(t, err, "failed to generate new certificates")

	err = framework.UpdateTLSSecret(ctx, testClientset, framework.WebhookNamespace, newCerts)
	require.NoError(t, err, "failed to update TLS secret")

	err = framework.UpdateWebhookCABundle(ctx, testClientset, newCerts.CACert)
	require.NoError(t, err, "failed to update webhook CA bundle")

	// Step 3: Wait for kubelet to propagate the secret update to the mounted volume
	// and for certwatcher to detect and reload the certificate.
	// Kubelet secret sync period is ~60s by default, certwatcher polls every 10s.
	// We poll for up to 90s, creating a test pod each attempt.
	ns2, err := framework.CreateTestNamespace(ctx, testClientset, "test-cert-reload-after")
	require.NoError(t, err, "failed to create namespace for post-rotation test")
	defer func() {
		_ = framework.DeleteNamespace(ctx, testClientset, ns2)
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns2, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	var lastErr error
	podIndex := 0
	deadline := time.Now().Add(90 * time.Second)

	for time.Now().Before(deadline) {
		podIndex++
		podName := fmt.Sprintf("after-rotation-%d", podIndex)

		testPod := framework.NewPodBuilder(ns2, podName).
			WithServiceAccount("test-sa").
			WithContainer("main", "busybox:latest").
			Build()

		createdPod, createErr := framework.CreatePodAndWait(ctx, testClientset, testPod)
		if createErr != nil {
			lastErr = createErr
			time.Sleep(10 * time.Second)
			continue
		}

		if len(createdPod.Spec.Containers) > 0 &&
			framework.HasEnvVar(&createdPod.Spec.Containers[0], framework.AWSRoleArnEnv) {
			// Webhook is working with the new certificates
			t.Logf("Webhook operational after cert rotation (attempt %d)", podIndex)
			lastErr = nil
			break
		}

		lastErr = fmt.Errorf("pod %s was not mutated by webhook", podName)
		time.Sleep(10 * time.Second)
	}

	require.NoError(t, lastErr, "webhook should work after certificate rotation")
}
