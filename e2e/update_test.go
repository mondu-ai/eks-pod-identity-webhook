package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"eks-pod-identity-webhook-e2e/framework"
)

// TestPodUpdateAfterServiceAccountAnnotated tests that a pod admitted before its ServiceAccount
// got the role-arn annotation can still be updated: a pod's volumes and env are immutable.
func TestPodUpdateAfterServiceAccountAnnotated(t *testing.T) {
	ctx := context.Background()

	// The chart sends only CREATE to the webhook, so the webhook itself must also leave UPDATE alone.
	restore, err := framework.SendPodUpdatesToWebhook(ctx, testClientset)
	require.NoError(t, err, "failed to send pod updates to the webhook")
	defer func() {
		_ = restore(context.Background()) //nolint:errcheck // cleanup in defer
	}()

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

	// kube-apiserver picks up the webhook's new rule asynchronously, so update until the webhook sees one.
	var updatedPod *corev1.Pod
	attempt := 0
	err = wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		before, err := framework.WebhookAdmissions(ctx, testClientset, admissionregistrationv1.Update)
		if err != nil {
			return false, err
		}

		attempt++
		patch := fmt.Sprintf(`{"metadata":{"labels":{"e2e-touched":"%d"}}}`, attempt)
		updatedPod, err = testClientset.CoreV1().Pods(ns).Patch(ctx, "test-pod", types.MergePatchType, []byte(patch), metav1.PatchOptions{})
		if err != nil {
			return false, err
		}

		after, err := framework.WebhookAdmissions(ctx, testClientset, admissionregistrationv1.Update)
		return after > before, err
	})
	require.NoError(t, err, "updating pod metadata should reach the webhook and not be rejected")
	assert.NotEmpty(t, updatedPod.Labels["e2e-touched"], "the label should be applied")
	assert.False(t, framework.HasEnvVar(&updatedPod.Spec.Containers[0], framework.AWSRoleArnEnv),
		"an update must not inject into an existing pod")
}
