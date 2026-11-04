package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"eks-pod-identity-webhook-e2e/framework"
)

// TestPodUpdateAfterServiceAccountAnnotated tests that a pod admitted before its ServiceAccount
// got the role-arn annotation can still be updated: a pod's volumes and env are immutable.
func TestPodUpdateAfterServiceAccountAnnotated(t *testing.T) {
	ctx := context.Background()

	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-pod-update")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(ctx, testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateServiceAccount(ctx, testClientset, ns, "test-sa")
	require.NoError(t, err, "failed to create service account")

	pod := framework.NewPodBuilder(ns, "test-pod").
		WithServiceAccount("test-sa").
		WithContainer("main", "busybox:latest").
		Build()

	createdPod, err := framework.CreatePodAndWait(ctx, testClientset, pod)
	require.NoError(t, err, "failed to create pod")
	require.False(t, framework.HasVolume(createdPod, framework.AWSTokenVolumeName),
		"pod should be admitted without injection while its ServiceAccount has no role-arn")

	err = framework.AnnotateServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to annotate service account")

	updatedPod, err := testClientset.CoreV1().Pods(ns).Patch(ctx, "test-pod", types.MergePatchType,
		[]byte(`{"metadata":{"labels":{"e2e-touched":"true"}}}`), metav1.PatchOptions{})
	require.NoError(t, err, "updating pod metadata should not be rejected")
	assert.Equal(t, "true", updatedPod.Labels["e2e-touched"], "the label should be applied")
	assert.False(t, framework.HasEnvVar(&updatedPod.Spec.Containers[0], framework.AWSRoleArnEnv),
		"an update must not inject into an existing pod")
}
