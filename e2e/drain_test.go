package e2e

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"eks-pod-identity-webhook-e2e/framework"
)

const (
	// drainHold outlasts the drain's 10s minimum, so only waiting on kube-apiserver's connections explains it.
	drainHold          = 30 * time.Second
	warmupBurst        = 30
	stoppingAdmitEvery = 5 * time.Second
)

// TestStoppingReplicaWaitsForApiserverConnections tests that a replica told to stop keeps serving until
// kube-apiserver has closed its keep-alive connections, and that pods admitted meanwhile are injected.
func TestStoppingReplicaWaitsForApiserverConnections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-drain")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(context.Background(), testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	pods, err := framework.WebhookPods(ctx, testClientset)
	require.NoError(t, err)
	require.Len(t, pods, 1, "the e2e webhook runs a single replica")
	stopping := pods[0].Name
	require.NotNil(t, pods[0].Spec.TerminationGracePeriodSeconds)
	gracePeriod := time.Duration(*pods[0].Spec.TerminationGracePeriodSeconds) * time.Second

	warmUp(ctx, t, ns)

	require.NoError(t, framework.RestartWebhook(ctx, testClientset))
	stopAt := waitForDeletion(ctx, t, stopping)

	missed := admitEvery(ctx, ns, stoppingAdmitEvery, func() bool { return gone(ctx, stopping) })

	time.Sleep(time.Until(stopAt.Add(drainHold)))
	pod, err := testClientset.CoreV1().Pods(framework.WebhookNamespace).Get(ctx, stopping, metav1.GetOptions{})
	require.NoError(t, err, "the replica exited before kube-apiserver closed its connections")
	require.NotEmpty(t, pod.Status.ContainerStatuses)
	assert.NotNil(t, pod.Status.ContainerStatuses[0].State.Running, "the replica should still serve while draining")

	err = wait.PollUntilContextTimeout(ctx, time.Second, gracePeriod, true, func(ctx context.Context) (bool, error) {
		return gone(ctx, stopping), nil
	})
	require.NoError(t, err, "the replica should exit within its grace period")
	t.Logf("replica %s exited %s after it was told to stop", stopping, time.Since(stopAt).Round(time.Second))

	assert.Empty(t, <-missed, "pods admitted while the replica stopped were not injected")
	require.NoError(t, framework.WaitForWebhookRollout(ctx, testClientset))
}

// warmUp fills kube-apiserver's keep-alive pool to the webhook with a burst of admissions.
func warmUp(ctx context.Context, t *testing.T, ns string) {
	t.Helper()

	reasons := make(chan string, warmupBurst)
	var wg sync.WaitGroup
	for range warmupBurst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reasons <- admitPod(ctx, burstClientset, ns)
		}()
	}
	wg.Wait()
	close(reasons)

	for reason := range reasons {
		require.Empty(t, reason, "warm-up admission was not injected")
	}
}

func waitForDeletion(ctx context.Context, t *testing.T, name string) time.Time {
	t.Helper()

	err := wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		pod, err := testClientset.CoreV1().Pods(framework.WebhookNamespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return err == nil && pod.DeletionTimestamp != nil, nil
	})
	require.NoError(t, err, "the replica was never told to stop")
	return time.Now()
}

func gone(ctx context.Context, name string) bool {
	_, err := testClientset.CoreV1().Pods(framework.WebhookNamespace).Get(ctx, name, metav1.GetOptions{})
	return apierrors.IsNotFound(err)
}

// admitEvery admits a pod at each interval until done reports true, then sends the failures.
func admitEvery(ctx context.Context, ns string, interval time.Duration, done func() bool) <-chan []string {
	missed := make(chan []string, 1)
	go func() {
		var reasons []string
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for !done() {
			if reason := admitPod(ctx, testClientset, ns); reason != "" {
				reasons = append(reasons, reason)
			}
			select {
			case <-ctx.Done():
				missed <- append(reasons, "context done: "+ctx.Err().Error())
				return
			case <-ticker.C:
			}
		}
		missed <- reasons
	}()
	return missed
}
