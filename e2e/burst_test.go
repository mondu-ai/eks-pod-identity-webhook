package e2e

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"eks-pod-identity-webhook-e2e/framework"
)

// burstSize is a few times the pods a busy minute boundary creates at once, when many CronJobs fire.
const burstSize = 100

// TestBurstOfPodAdmissions tests that every pod in a burst of concurrent admissions is injected.
func TestBurstOfPodAdmissions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-burst")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(context.Background(), testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	reasons := make(chan string, burstSize)
	var wg sync.WaitGroup
	for range burstSize {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reasons <- admitPod(ctx, burstClientset, ns)
		}()
	}
	wg.Wait()
	close(reasons)

	var missed []string
	for reason := range reasons {
		if reason != "" {
			missed = append(missed, reason)
		}
	}
	assert.Empty(t, missed, "%d of %d pods in the burst were not injected", len(missed), burstSize)
}
