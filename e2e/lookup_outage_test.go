package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"eks-pod-identity-webhook-e2e/framework"
)

// lookupOutage stays well inside client-go's 10 retries, which is the window a retryable denial buys.
const lookupOutage = 3 * time.Second

// TestPodAdmissionSurvivesServiceAccountLookupOutage tests that a pod created while the webhook
// cannot read ServiceAccounts is admitted with injection once it can, without the caller retrying.
func TestPodAdmissionSurvivesServiceAccountLookupOutage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-lookup-outage")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(context.Background(), testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	restore, err := framework.RevokeWebhookRBAC(ctx, testClientset)
	if restore != nil {
		defer func() {
			_ = restore(context.Background()) //nolint:errcheck // cleanup in defer
		}()
	}
	require.NoError(t, err, "failed to revoke webhook RBAC")

	outageStart := time.Now()
	time.AfterFunc(lookupOutage, func() {
		_ = restore(context.Background()) //nolint:errcheck // checked again after the pod is created
	})

	pod := framework.NewPodBuilder(ns, "test-pod").
		WithServiceAccount("test-sa").
		WithContainer("main", "busybox:latest").
		Build()

	createdPod, err := framework.CreatePodAndWait(ctx, testClientset, pod)
	require.NoError(t, err, "pod creation should outlast a short ServiceAccount lookup outage")
	assert.GreaterOrEqual(t, time.Since(outageStart), lookupOutage,
		"the pod can only have been admitted after the outage, through retries")
	require.NoError(t, restore(ctx), "failed to restore webhook RBAC")
	require.Len(t, createdPod.Spec.Containers, 1)
	assert.True(t, framework.HasEnvVar(&createdPod.Spec.Containers[0], framework.AWSRoleArnEnv),
		"pod should be injected once the webhook can read its ServiceAccount again")
}
