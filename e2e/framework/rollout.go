package framework

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const (
	webhookRolloutTimeout = 3 * time.Minute
	webhookContainerName  = "webhook"
)

// RestartWebhook triggers a rolling restart of the webhook deployment, as `kubectl rollout restart` does.
func RestartWebhook(ctx context.Context, client kubernetes.Interface) error {
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		time.Now().Format(time.RFC3339Nano))

	_, err := client.AppsV1().Deployments(WebhookNamespace).Patch(
		ctx, helmDeploymentName, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to restart webhook deployment: %w", err)
	}
	return nil
}

// WaitForWebhookRollout waits until the deployment runs on updated replicas only and every old pod is gone.
func WaitForWebhookRollout(ctx context.Context, client kubernetes.Interface) error {
	return wait.PollUntilContextTimeout(ctx, helmDeploymentPollInterval, webhookRolloutTimeout, true,
		func(ctx context.Context) (bool, error) {
			deployment, err := client.AppsV1().Deployments(WebhookNamespace).Get(ctx, helmDeploymentName, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}

			replicas := *deployment.Spec.Replicas
			status := deployment.Status
			if status.ObservedGeneration < deployment.Generation ||
				status.UpdatedReplicas != replicas || status.AvailableReplicas != replicas {
				return false, nil
			}

			selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
			if err != nil {
				return false, fmt.Errorf("failed to parse webhook deployment selector: %w", err)
			}

			// Terminating pods stay listed until their process exits, which is the window under test.
			pods, err := client.CoreV1().Pods(WebhookNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
			if err != nil {
				return false, nil
			}
			return len(pods.Items) == int(replicas), nil
		},
	)
}

// ConfigureWebhookDrain sets the webhook's drain timeout and the grace period that covers it, as the chart
// will once published, and waits for the webhook pods to roll over.
func ConfigureWebhookDrain(ctx context.Context, client kubernetes.Interface, gracePeriodSeconds int64, drainTimeout string) error {
	patch := fmt.Sprintf(
		`{"spec":{"template":{"spec":{"terminationGracePeriodSeconds":%d,"containers":[{"name":%q,"env":[{"name":"SHUTDOWN_DRAIN_TIMEOUT","value":%q}]}]}}}}`,
		gracePeriodSeconds, webhookContainerName, drainTimeout,
	)

	_, err := client.AppsV1().Deployments(WebhookNamespace).Patch(
		ctx, helmDeploymentName, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to configure webhook drain: %w", err)
	}
	return WaitForWebhookRollout(ctx, client)
}

// WebhookPods lists the webhook deployment's pods, terminating ones included.
func WebhookPods(ctx context.Context, client kubernetes.Interface) ([]corev1.Pod, error) {
	deployment, err := client.AppsV1().Deployments(WebhookNamespace).Get(ctx, helmDeploymentName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get webhook deployment: %w", err)
	}

	selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("failed to parse webhook deployment selector: %w", err)
	}

	pods, err := client.CoreV1().Pods(WebhookNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, fmt.Errorf("failed to list webhook pods: %w", err)
	}
	return pods.Items, nil
}
