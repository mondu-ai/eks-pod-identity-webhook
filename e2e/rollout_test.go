package e2e

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"eks-pod-identity-webhook-e2e/framework"
)

const (
	rolloutRounds  = 2
	rolloutWorkers = 8
)

// TestPodsInjectedDuringWebhookRollout tests that no pod admitted while the webhook rolls
// over to new replicas slips through without injection.
func TestPodsInjectedDuringWebhookRollout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-rollout")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(context.Background(), testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	for round := 1; round <= rolloutRounds; round++ {
		admitted, missed := admitDuringRollout(ctx, t, ns)
		t.Logf("rollout %d: %d pods admitted, %d without injection", round, admitted, len(missed))
		assert.Empty(t, missed, "rollout %d: pods admitted without injection", round)
	}
}

// admitDuringRollout keeps admitting pods from the start of a webhook restart until its old pods are gone.
func admitDuringRollout(ctx context.Context, t *testing.T, ns string) (int, []string) {
	t.Helper()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var admitted int
	var missed []string

	for range rolloutWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				reason := admitPod(ctx, burstClientset, ns)
				mu.Lock()
				admitted++
				if reason != "" {
					missed = append(missed, reason)
				}
				mu.Unlock()
			}
		}()
	}

	err := framework.RestartWebhook(ctx, testClientset)
	if err == nil {
		err = framework.WaitForWebhookRollout(ctx, testClientset)
	}
	close(stop)
	wg.Wait()

	require.NoError(t, err, "webhook rollout did not complete")
	return admitted, missed
}

// admitPod dry-runs a pod creation, which goes through admission without persisting the pod,
// and describes the failure if the pod was not injected.
func admitPod(ctx context.Context, client kubernetes.Interface, ns string) string {
	pod := framework.NewPodBuilder(ns, "").
		WithGenerateName("admitted-").
		WithServiceAccount("test-sa").
		WithContainer("main", "busybox:latest").
		Build()

	at := time.Now().Format(time.RFC3339Nano)
	admitted, err := client.CoreV1().Pods(ns).Create(ctx, pod,
		metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	if err != nil {
		return fmt.Sprintf("%s: create failed: %v", at, err)
	}
	if !framework.HasEnvVar(&admitted.Spec.Containers[0], framework.AWSRoleArnEnv) {
		return at + ": admitted without injection"
	}
	return ""
}
