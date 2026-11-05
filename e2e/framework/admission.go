package framework

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const webhookAdmissionsMetric = "apiserver_admission_webhook_admission_duration_seconds_count"

// SendPodUpdatesToWebhook adds UPDATE to the webhook's rule, as charts before 0.4.0 registered it.
// The returned function restores the rule's original operations.
func SendPodUpdatesToWebhook(ctx context.Context, client kubernetes.Interface) (func(context.Context) error, error) {
	webhook, err := getWebhook(ctx, client)
	if err != nil {
		return nil, err
	}
	original := slices.Clone(webhook.Rules[0].Operations)

	if !slices.Contains(original, admissionregistrationv1.Update) {
		if err := setWebhookOperations(ctx, client, append(slices.Clone(original), admissionregistrationv1.Update)); err != nil {
			return nil, err
		}
	}

	return func(ctx context.Context) error {
		return setWebhookOperations(ctx, client, original)
	}, nil
}

// WebhookAdmissions counts the calls kube-apiserver has made to the webhook for an operation.
func WebhookAdmissions(ctx context.Context, client kubernetes.Interface, operation admissionregistrationv1.OperationType) (float64, error) {
	webhook, err := getWebhook(ctx, client)
	if err != nil {
		return 0, err
	}

	raw, err := client.CoreV1().RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to read kube-apiserver metrics: %w", err)
	}

	name := fmt.Sprintf("name=%q", webhook.Name)
	op := fmt.Sprintf("operation=%q", operation)
	var total float64
	for line := range strings.Lines(string(raw)) {
		if !strings.HasPrefix(line, webhookAdmissionsMetric+"{") || !strings.Contains(line, name) || !strings.Contains(line, op) {
			continue
		}
		fields := strings.Fields(line)
		count, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse metric line %q: %w", line, err)
		}
		total += count
	}
	return total, nil
}

func getWebhook(ctx context.Context, client kubernetes.Interface) (*admissionregistrationv1.MutatingWebhook, error) {
	config, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, helmWebhookConfigName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get webhook configuration: %w", err)
	}
	if len(config.Webhooks) == 0 || len(config.Webhooks[0].Rules) == 0 {
		return nil, fmt.Errorf("webhook configuration %s has no rules", helmWebhookConfigName)
	}
	return &config.Webhooks[0], nil
}

func setWebhookOperations(ctx context.Context, client kubernetes.Interface, operations []admissionregistrationv1.OperationType) error {
	value, err := json.Marshal(operations)
	if err != nil {
		return fmt.Errorf("failed to encode webhook operations: %w", err)
	}

	patch := fmt.Sprintf(`[{"op":"replace","path":"/webhooks/0/rules/0/operations","value":%s}]`, value)
	_, err = client.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(
		ctx, helmWebhookConfigName, types.JSONPatchType, []byte(patch), metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to set webhook operations to %v: %w", operations, err)
	}
	return nil
}
