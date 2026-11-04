package framework

import (
	"context"
	"fmt"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const (
	webhookClusterRoleBindingName = "eks-pod-identity-webhook-crb"
	rbacPropagationTimeout        = 30 * time.Second
	rbacPropagationPollInterval   = 200 * time.Millisecond
)

// RevokeWebhookRBAC deletes the webhook's ClusterRoleBinding and waits until the webhook can no
// longer read ServiceAccounts. The returned function puts the binding back.
func RevokeWebhookRBAC(ctx context.Context, client kubernetes.Interface) (func(context.Context) error, error) {
	binding, err := client.RbacV1().ClusterRoleBindings().Get(ctx, webhookClusterRoleBindingName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get webhook cluster role binding: %w", err)
	}
	if len(binding.Subjects) == 0 {
		return nil, fmt.Errorf("webhook cluster role binding %s has no subjects", binding.Name)
	}
	webhook := binding.Subjects[0]

	if err := client.RbacV1().ClusterRoleBindings().Delete(ctx, binding.Name, metav1.DeleteOptions{}); err != nil {
		return nil, fmt.Errorf("failed to delete webhook cluster role binding: %w", err)
	}

	// restore is safe to call any number of times, concurrently too: every later test needs the binding back.
	restore := func(ctx context.Context) error {
		recreated := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: binding.Name, Labels: binding.Labels, Annotations: binding.Annotations},
			RoleRef:    binding.RoleRef,
			Subjects:   binding.Subjects,
		}
		var lastErr error
		err := wait.PollUntilContextTimeout(ctx, rbacPropagationPollInterval, rbacPropagationTimeout, true,
			func(ctx context.Context) (bool, error) {
				_, lastErr = client.RbacV1().ClusterRoleBindings().Create(ctx, recreated, metav1.CreateOptions{})
				return lastErr == nil || apierrors.IsAlreadyExists(lastErr), nil
			},
		)
		if err != nil {
			return fmt.Errorf("failed to restore webhook cluster role binding: %w (last error: %w)", err, lastErr)
		}
		return nil
	}

	err = wait.PollUntilContextTimeout(ctx, rbacPropagationPollInterval, rbacPropagationTimeout, true,
		func(ctx context.Context) (bool, error) {
			allowed, err := canGetServiceAccounts(ctx, client, webhook)
			return err == nil && !allowed, nil
		},
	)
	if err != nil {
		return restore, fmt.Errorf("webhook kept access to service accounts after its binding was deleted: %w", err)
	}
	return restore, nil
}

func canGetServiceAccounts(ctx context.Context, client kubernetes.Interface, sa rbacv1.Subject) (bool, error) {
	review := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   fmt.Sprintf("system:serviceaccount:%s:%s", sa.Namespace, sa.Name),
			Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + sa.Namespace},
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     "get",
				Resource: "serviceaccounts",
			},
		},
	}
	res, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to review webhook access: %w", err)
	}
	return res.Status.Allowed, nil
}
