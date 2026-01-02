// Package framework provides test utilities for e2e tests of the EKS Pod Identity Webhook.
package framework

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// Constants matching the webhook injection values
const (
	AWSTokenVolumeName     = "aws-token"
	AWSTokenMountPath      = "/var/run/secrets/eks.amazonaws.com/serviceaccount" // #nosec G101 -- not a credential, just a path
	AWSWebIdentityTokenEnv = "AWS_WEB_IDENTITY_TOKEN_FILE"                       // #nosec G101 -- not a credential, just an env var name
	AWSRoleArnEnv          = "AWS_ROLE_ARN"
	AWSRegionEnv           = "AWS_REGION"
	AWSDefaultRegionEnv    = "AWS_DEFAULT_REGION"
	AWSRoleSessionNameEnv  = "AWS_ROLE_SESSION_NAME"
	RoleArnAnnotation      = "eks.amazonaws.com/role-arn"
)

// CreateTestNamespace creates a namespace with a generated name using the given prefix.
func CreateTestNamespace(ctx context.Context, client kubernetes.Interface, prefix string) (string, error) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: prefix + "-",
		},
	}
	created, err := client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create namespace with prefix %s: %w", prefix, err)
	}
	return created.Name, nil
}

// DeleteNamespace deletes the namespace with the given name.
func DeleteNamespace(ctx context.Context, client kubernetes.Interface, name string) error {
	err := client.CoreV1().Namespaces().Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete namespace %s: %w", name, err)
	}
	return nil
}

// CreateAnnotatedServiceAccount creates a ServiceAccount with the eks.amazonaws.com/role-arn annotation.
func CreateAnnotatedServiceAccount(ctx context.Context, client kubernetes.Interface, namespace, name, roleArn string) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				RoleArnAnnotation: roleArn,
			},
		},
	}
	_, err := client.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create annotated service account %s/%s: %w", namespace, name, err)
	}
	return nil
}

// CreateServiceAccount creates a ServiceAccount without any annotations.
func CreateServiceAccount(ctx context.Context, client kubernetes.Interface, namespace, name string) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	_, err := client.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service account %s/%s: %w", namespace, name, err)
	}
	return nil
}

// CreatePodAndWait creates a pod and waits for it to exist (webhook processed), returning the final state.
func CreatePodAndWait(ctx context.Context, client kubernetes.Interface, pod *corev1.Pod) (*corev1.Pod, error) {
	created, err := client.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	var finalPod *corev1.Pod
	err = wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		p, getErr := client.CoreV1().Pods(created.Namespace).Get(ctx, created.Name, metav1.GetOptions{})
		if getErr != nil {
			return false, nil
		}
		finalPod = p
		return true, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed waiting for pod %s/%s to exist: %w", created.Namespace, created.Name, err)
	}

	return finalPod, nil
}

// PodBuilder provides a fluent interface for building Pod specifications.
type PodBuilder struct {
	namespace          string
	name               string
	generateName       string
	serviceAccountName string
	containers         []corev1.Container
	initContainers     []corev1.Container
}

// NewPodBuilder creates a new PodBuilder with the given namespace and name.
func NewPodBuilder(namespace, name string) *PodBuilder {
	return &PodBuilder{
		namespace:      namespace,
		name:           name,
		containers:     []corev1.Container{},
		initContainers: []corev1.Container{},
	}
}

// WithGenerateName sets the GenerateName field instead of Name.
func (b *PodBuilder) WithGenerateName(generateName string) *PodBuilder {
	b.generateName = generateName
	b.name = ""
	return b
}

// WithServiceAccount sets the ServiceAccountName for the pod.
func (b *PodBuilder) WithServiceAccount(name string) *PodBuilder {
	b.serviceAccountName = name
	return b
}

// WithContainer adds a container with the given name and image.
func (b *PodBuilder) WithContainer(name, image string) *PodBuilder {
	b.containers = append(b.containers, corev1.Container{
		Name:  name,
		Image: image,
	})
	return b
}

// WithInitContainer adds an init container with the given name and image.
func (b *PodBuilder) WithInitContainer(name, image string) *PodBuilder {
	b.initContainers = append(b.initContainers, corev1.Container{
		Name:  name,
		Image: image,
	})
	return b
}

// WithEnvVar adds an environment variable to the last added container.
// If no containers exist, this is a no-op.
func (b *PodBuilder) WithEnvVar(name, value string) *PodBuilder {
	if len(b.containers) == 0 {
		return b
	}
	lastIdx := len(b.containers) - 1
	b.containers[lastIdx].Env = append(b.containers[lastIdx].Env, corev1.EnvVar{
		Name:  name,
		Value: value,
	})
	return b
}

// WithContainerEnvVar adds an environment variable to a specific container by index.
func (b *PodBuilder) WithContainerEnvVar(containerIndex int, name, value string) *PodBuilder {
	if containerIndex < 0 || containerIndex >= len(b.containers) {
		return b
	}
	b.containers[containerIndex].Env = append(b.containers[containerIndex].Env, corev1.EnvVar{
		Name:  name,
		Value: value,
	})
	return b
}

// Build creates and returns the Pod object.
func (b *PodBuilder) Build() *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: b.namespace,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: b.serviceAccountName,
			Containers:         b.containers,
			InitContainers:     b.initContainers,
		},
	}

	if b.generateName != "" {
		pod.GenerateName = b.generateName
	} else {
		pod.Name = b.name
	}

	return pod
}

// HasVolume checks if the pod has a volume with the given name.
func HasVolume(pod *corev1.Pod, volumeName string) bool {
	return GetVolume(pod, volumeName) != nil
}

// GetVolume returns a pointer to the volume with the given name, or nil if not found.
func GetVolume(pod *corev1.Pod, volumeName string) *corev1.Volume {
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == volumeName {
			return &pod.Spec.Volumes[i]
		}
	}
	return nil
}

// HasVolumeMount checks if the container has a volume mount with the given name.
func HasVolumeMount(container *corev1.Container, volumeName string) bool {
	return GetVolumeMount(container, volumeName) != nil
}

// GetVolumeMount returns a pointer to the volume mount with the given name, or nil if not found.
func GetVolumeMount(container *corev1.Container, volumeName string) *corev1.VolumeMount {
	for i := range container.VolumeMounts {
		if container.VolumeMounts[i].Name == volumeName {
			return &container.VolumeMounts[i]
		}
	}
	return nil
}

// HasEnvVar checks if the container has an environment variable with the given name.
func HasEnvVar(container *corev1.Container, envName string) bool {
	return GetEnvVar(container, envName) != nil
}

// GetEnvVar returns a pointer to the environment variable with the given name, or nil if not found.
func GetEnvVar(container *corev1.Container, envName string) *corev1.EnvVar {
	for i := range container.Env {
		if container.Env[i].Name == envName {
			return &container.Env[i]
		}
	}
	return nil
}
