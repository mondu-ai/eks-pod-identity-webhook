// Package e2e contains end-to-end tests for the EKS Pod Identity Webhook.
package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"eks-pod-identity-webhook-e2e/framework"
)

const (
	testRoleArn = "arn:aws:iam::123456789012:role/test-role"
	awsRegion   = "us-east-1"
)

// TestPodWithAnnotatedServiceAccount tests that a pod using an annotated ServiceAccount
// receives all the expected AWS credential injections.
func TestPodWithAnnotatedServiceAccount(t *testing.T) {
	ctx := context.Background()

	// Setup: create namespace and annotated ServiceAccount
	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-annotated-sa")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(ctx, testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	// Create pod using the annotated ServiceAccount
	pod := framework.NewPodBuilder(ns, "test-pod").
		WithServiceAccount("test-sa").
		WithContainer("main", "busybox:latest").
		Build()

	createdPod, err := framework.CreatePodAndWait(ctx, testClientset, pod)
	require.NoError(t, err, "failed to create pod")

	t.Run("has aws-token volume with projected type", func(t *testing.T) {
		volume := framework.GetVolume(createdPod, framework.AWSTokenVolumeName)
		require.NotNil(t, volume, "aws-token volume should exist")

		require.NotNil(t, volume.Projected, "volume should be of projected type")

		// Verify the projected volume has the correct configuration
		projected := volume.Projected
		require.Len(t, projected.Sources, 1, "should have exactly one projection source")

		tokenProjection := projected.Sources[0].ServiceAccountToken
		require.NotNil(t, tokenProjection, "should have ServiceAccountToken projection")
		assert.Equal(t, "sts.amazonaws.com", tokenProjection.Audience, "audience should be sts.amazonaws.com")
		assert.Equal(t, "token", tokenProjection.Path, "token path should be 'token'")
	})

	t.Run("container has volume mount at correct path", func(t *testing.T) {
		require.Len(t, createdPod.Spec.Containers, 1, "should have exactly one container")
		container := &createdPod.Spec.Containers[0]

		volumeMount := framework.GetVolumeMount(container, framework.AWSTokenVolumeName)
		require.NotNil(t, volumeMount, "container should have aws-token volume mount")

		assert.Equal(t, framework.AWSTokenMountPath, volumeMount.MountPath, "mount path should match expected path")
		assert.True(t, volumeMount.ReadOnly, "volume mount should be read-only")
	})

	t.Run("container has all 5 AWS env vars with correct values", func(t *testing.T) {
		require.Len(t, createdPod.Spec.Containers, 1, "should have exactly one container")
		container := &createdPod.Spec.Containers[0]

		// AWS_WEB_IDENTITY_TOKEN_FILE
		tokenFileEnv := framework.GetEnvVar(container, framework.AWSWebIdentityTokenEnv)
		require.NotNil(t, tokenFileEnv, "AWS_WEB_IDENTITY_TOKEN_FILE env var should exist")
		expectedTokenPath := framework.AWSTokenMountPath + "/token"
		assert.Equal(t, expectedTokenPath, tokenFileEnv.Value, "AWS_WEB_IDENTITY_TOKEN_FILE should have correct value")

		// AWS_ROLE_ARN
		roleArnEnv := framework.GetEnvVar(container, framework.AWSRoleArnEnv)
		require.NotNil(t, roleArnEnv, "AWS_ROLE_ARN env var should exist")
		assert.Equal(t, testRoleArn, roleArnEnv.Value, "AWS_ROLE_ARN should match the ServiceAccount annotation")

		// AWS_REGION
		regionEnv := framework.GetEnvVar(container, framework.AWSRegionEnv)
		require.NotNil(t, regionEnv, "AWS_REGION env var should exist")
		assert.Equal(t, awsRegion, regionEnv.Value, "AWS_REGION should match webhook default")

		// AWS_DEFAULT_REGION
		defaultRegionEnv := framework.GetEnvVar(container, framework.AWSDefaultRegionEnv)
		require.NotNil(t, defaultRegionEnv, "AWS_DEFAULT_REGION env var should exist")
		assert.Equal(t, awsRegion, defaultRegionEnv.Value, "AWS_DEFAULT_REGION should match webhook default")

		// AWS_ROLE_SESSION_NAME
		sessionNameEnv := framework.GetEnvVar(container, framework.AWSRoleSessionNameEnv)
		require.NotNil(t, sessionNameEnv, "AWS_ROLE_SESSION_NAME env var should exist")
		assert.NotEmpty(t, sessionNameEnv.Value, "AWS_ROLE_SESSION_NAME should not be empty")
	})
}

// TestPodWithoutAnnotation tests that a pod using a ServiceAccount without
// the role-arn annotation does not receive any AWS credential injections.
func TestPodWithoutAnnotation(t *testing.T) {
	ctx := context.Background()

	// Setup: create namespace and ServiceAccount WITHOUT annotation
	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-no-annotation")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(ctx, testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateServiceAccount(ctx, testClientset, ns, "test-sa")
	require.NoError(t, err, "failed to create service account without annotation")

	// Create pod using the non-annotated ServiceAccount
	pod := framework.NewPodBuilder(ns, "test-pod").
		WithServiceAccount("test-sa").
		WithContainer("main", "busybox:latest").
		Build()

	createdPod, err := framework.CreatePodAndWait(ctx, testClientset, pod)
	require.NoError(t, err, "failed to create pod")

	t.Run("does not have aws-token volume", func(t *testing.T) {
		assert.False(t, framework.HasVolume(createdPod, framework.AWSTokenVolumeName),
			"pod should NOT have aws-token volume")
	})

	t.Run("does not have AWS env vars", func(t *testing.T) {
		require.Len(t, createdPod.Spec.Containers, 1, "should have exactly one container")
		container := &createdPod.Spec.Containers[0]

		assert.False(t, framework.HasEnvVar(container, framework.AWSWebIdentityTokenEnv),
			"container should NOT have AWS_WEB_IDENTITY_TOKEN_FILE")
		assert.False(t, framework.HasEnvVar(container, framework.AWSRoleArnEnv),
			"container should NOT have AWS_ROLE_ARN")
		assert.False(t, framework.HasEnvVar(container, framework.AWSRegionEnv),
			"container should NOT have AWS_REGION")
		assert.False(t, framework.HasEnvVar(container, framework.AWSDefaultRegionEnv),
			"container should NOT have AWS_DEFAULT_REGION")
		assert.False(t, framework.HasEnvVar(container, framework.AWSRoleSessionNameEnv),
			"container should NOT have AWS_ROLE_SESSION_NAME")
	})
}

// TestMultiContainerPod tests that all containers in a multi-container pod
// receive the AWS credential injections.
func TestMultiContainerPod(t *testing.T) {
	ctx := context.Background()

	// Setup: create namespace and annotated ServiceAccount
	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-multi-container")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(ctx, testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	// Create pod with 3 containers
	pod := framework.NewPodBuilder(ns, "test-pod").
		WithServiceAccount("test-sa").
		WithContainer("container-1", "busybox:latest").
		WithContainer("container-2", "busybox:latest").
		WithContainer("container-3", "busybox:latest").
		Build()

	createdPod, err := framework.CreatePodAndWait(ctx, testClientset, pod)
	require.NoError(t, err, "failed to create pod")

	require.Len(t, createdPod.Spec.Containers, 3, "should have exactly 3 containers")

	for i, container := range createdPod.Spec.Containers {
		container := container // capture range variable
		t.Run("container "+container.Name+" has volume mount and env vars", func(t *testing.T) {
			// Check volume mount
			volumeMount := framework.GetVolumeMount(&createdPod.Spec.Containers[i], framework.AWSTokenVolumeName)
			require.NotNil(t, volumeMount, "container %s should have aws-token volume mount", container.Name)
			assert.Equal(t, framework.AWSTokenMountPath, volumeMount.MountPath)
			assert.True(t, volumeMount.ReadOnly)

			// Check all 5 env vars
			assert.True(t, framework.HasEnvVar(&createdPod.Spec.Containers[i], framework.AWSWebIdentityTokenEnv),
				"container %s should have AWS_WEB_IDENTITY_TOKEN_FILE", container.Name)
			assert.True(t, framework.HasEnvVar(&createdPod.Spec.Containers[i], framework.AWSRoleArnEnv),
				"container %s should have AWS_ROLE_ARN", container.Name)
			assert.True(t, framework.HasEnvVar(&createdPod.Spec.Containers[i], framework.AWSRegionEnv),
				"container %s should have AWS_REGION", container.Name)
			assert.True(t, framework.HasEnvVar(&createdPod.Spec.Containers[i], framework.AWSDefaultRegionEnv),
				"container %s should have AWS_DEFAULT_REGION", container.Name)
			assert.True(t, framework.HasEnvVar(&createdPod.Spec.Containers[i], framework.AWSRoleSessionNameEnv),
				"container %s should have AWS_ROLE_SESSION_NAME", container.Name)
		})
	}
}

// TestInitContainerInjection tests that init containers also receive
// the AWS credential injections.
func TestInitContainerInjection(t *testing.T) {
	ctx := context.Background()

	// Setup: create namespace and annotated ServiceAccount
	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-init-containers")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(ctx, testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	// Create pod with 2 init containers and 1 regular container
	pod := framework.NewPodBuilder(ns, "test-pod").
		WithServiceAccount("test-sa").
		WithInitContainer("init-1", "busybox:latest").
		WithInitContainer("init-2", "busybox:latest").
		WithContainer("main", "busybox:latest").
		Build()

	createdPod, err := framework.CreatePodAndWait(ctx, testClientset, pod)
	require.NoError(t, err, "failed to create pod")

	require.Len(t, createdPod.Spec.InitContainers, 2, "should have exactly 2 init containers")
	require.Len(t, createdPod.Spec.Containers, 1, "should have exactly 1 container")

	// Helper function to verify container has all mutations
	verifyContainerMutations := func(t *testing.T, container *corev1.Container, containerType string) {
		t.Helper()

		// Check volume mount
		volumeMount := framework.GetVolumeMount(container, framework.AWSTokenVolumeName)
		require.NotNil(t, volumeMount, "%s %s should have aws-token volume mount", containerType, container.Name)
		assert.Equal(t, framework.AWSTokenMountPath, volumeMount.MountPath)
		assert.True(t, volumeMount.ReadOnly)

		// Check all 5 env vars
		assert.True(t, framework.HasEnvVar(container, framework.AWSWebIdentityTokenEnv),
			"%s %s should have AWS_WEB_IDENTITY_TOKEN_FILE", containerType, container.Name)
		assert.True(t, framework.HasEnvVar(container, framework.AWSRoleArnEnv),
			"%s %s should have AWS_ROLE_ARN", containerType, container.Name)
		assert.True(t, framework.HasEnvVar(container, framework.AWSRegionEnv),
			"%s %s should have AWS_REGION", containerType, container.Name)
		assert.True(t, framework.HasEnvVar(container, framework.AWSDefaultRegionEnv),
			"%s %s should have AWS_DEFAULT_REGION", containerType, container.Name)
		assert.True(t, framework.HasEnvVar(container, framework.AWSRoleSessionNameEnv),
			"%s %s should have AWS_ROLE_SESSION_NAME", containerType, container.Name)
	}

	t.Run("init containers have mutations", func(t *testing.T) {
		for i := range createdPod.Spec.InitContainers {
			verifyContainerMutations(t, &createdPod.Spec.InitContainers[i], "init container")
		}
	})

	t.Run("regular container has mutations", func(t *testing.T) {
		verifyContainerMutations(t, &createdPod.Spec.Containers[0], "container")
	})
}

// TestRoleSessionNameWithPodName tests that when a pod has an explicit name,
// the AWS_ROLE_SESSION_NAME is set to that pod name.
func TestRoleSessionNameWithPodName(t *testing.T) {
	ctx := context.Background()

	// Setup: create namespace and annotated ServiceAccount
	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-session-name")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(ctx, testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	// Create pod with explicit name
	podName := "my-explicit-pod-name"
	pod := framework.NewPodBuilder(ns, podName).
		WithServiceAccount("test-sa").
		WithContainer("main", "busybox:latest").
		Build()

	createdPod, err := framework.CreatePodAndWait(ctx, testClientset, pod)
	require.NoError(t, err, "failed to create pod")

	require.Len(t, createdPod.Spec.Containers, 1, "should have exactly one container")
	container := &createdPod.Spec.Containers[0]

	sessionNameEnv := framework.GetEnvVar(container, framework.AWSRoleSessionNameEnv)
	require.NotNil(t, sessionNameEnv, "AWS_ROLE_SESSION_NAME env var should exist")
	assert.Equal(t, podName, sessionNameEnv.Value, "AWS_ROLE_SESSION_NAME should equal the pod name")
}

// TestRoleSessionNameWithGenerateName tests that when a pod uses GenerateName
// instead of an explicit name, the AWS_ROLE_SESSION_NAME starts with the GenerateName prefix.
func TestRoleSessionNameWithGenerateName(t *testing.T) {
	ctx := context.Background()

	// Setup: create namespace and annotated ServiceAccount
	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-generate-name")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(ctx, testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	// Create pod with GenerateName (no explicit name)
	generateNamePrefix := "my-generated-pod-"
	pod := framework.NewPodBuilder(ns, "").
		WithGenerateName(generateNamePrefix).
		WithServiceAccount("test-sa").
		WithContainer("main", "busybox:latest").
		Build()

	createdPod, err := framework.CreatePodAndWait(ctx, testClientset, pod)
	require.NoError(t, err, "failed to create pod")

	require.Len(t, createdPod.Spec.Containers, 1, "should have exactly one container")
	container := &createdPod.Spec.Containers[0]

	sessionNameEnv := framework.GetEnvVar(container, framework.AWSRoleSessionNameEnv)
	require.NotNil(t, sessionNameEnv, "AWS_ROLE_SESSION_NAME env var should exist")

	// The session name should start with the prefix (without trailing dash) followed by additional characters
	expectedPrefix := strings.TrimSuffix(generateNamePrefix, "-")
	assert.True(t, strings.HasPrefix(sessionNameEnv.Value, expectedPrefix),
		"AWS_ROLE_SESSION_NAME '%s' should start with GenerateName prefix '%s'",
		sessionNameEnv.Value, expectedPrefix)
}

// TestExistingEnvVarsNotOverwritten tests that pre-existing AWS environment variables
// in a container are preserved and not overwritten by the webhook.
func TestExistingEnvVarsNotOverwritten(t *testing.T) {
	ctx := context.Background()

	// Setup: create namespace and annotated ServiceAccount
	ns, err := framework.CreateTestNamespace(ctx, testClientset, "test-existing-env")
	require.NoError(t, err, "failed to create test namespace")
	defer func() {
		_ = framework.DeleteNamespace(ctx, testClientset, ns) //nolint:errcheck // cleanup in defer
	}()

	err = framework.CreateAnnotatedServiceAccount(ctx, testClientset, ns, "test-sa", testRoleArn)
	require.NoError(t, err, "failed to create annotated service account")

	// Create pod with pre-existing AWS_ROLE_ARN env var
	existingRoleArn := "arn:aws:iam::999999999999:role/existing-role"
	pod := framework.NewPodBuilder(ns, "test-pod").
		WithServiceAccount("test-sa").
		WithContainer("main", "busybox:latest").
		WithEnvVar(framework.AWSRoleArnEnv, existingRoleArn).
		Build()

	createdPod, err := framework.CreatePodAndWait(ctx, testClientset, pod)
	require.NoError(t, err, "failed to create pod")

	require.Len(t, createdPod.Spec.Containers, 1, "should have exactly one container")
	container := &createdPod.Spec.Containers[0]

	t.Run("existing AWS_ROLE_ARN is preserved", func(t *testing.T) {
		roleArnEnv := framework.GetEnvVar(container, framework.AWSRoleArnEnv)
		require.NotNil(t, roleArnEnv, "AWS_ROLE_ARN env var should exist")
		assert.Equal(t, existingRoleArn, roleArnEnv.Value,
			"existing AWS_ROLE_ARN value should be preserved, not overwritten")
	})

	t.Run("other AWS env vars are still injected", func(t *testing.T) {
		// AWS_WEB_IDENTITY_TOKEN_FILE should be injected
		tokenFileEnv := framework.GetEnvVar(container, framework.AWSWebIdentityTokenEnv)
		require.NotNil(t, tokenFileEnv, "AWS_WEB_IDENTITY_TOKEN_FILE should be injected")
		expectedTokenPath := framework.AWSTokenMountPath + "/token"
		assert.Equal(t, expectedTokenPath, tokenFileEnv.Value)

		// AWS_REGION should be injected
		regionEnv := framework.GetEnvVar(container, framework.AWSRegionEnv)
		require.NotNil(t, regionEnv, "AWS_REGION should be injected")
		assert.Equal(t, awsRegion, regionEnv.Value)

		// AWS_DEFAULT_REGION should be injected
		defaultRegionEnv := framework.GetEnvVar(container, framework.AWSDefaultRegionEnv)
		require.NotNil(t, defaultRegionEnv, "AWS_DEFAULT_REGION should be injected")
		assert.Equal(t, awsRegion, defaultRegionEnv.Value)

		// AWS_ROLE_SESSION_NAME should be injected
		sessionNameEnv := framework.GetEnvVar(container, framework.AWSRoleSessionNameEnv)
		require.NotNil(t, sessionNameEnv, "AWS_ROLE_SESSION_NAME should be injected")
		assert.NotEmpty(t, sessionNameEnv.Value)
	})

	t.Run("volume and volume mount are still added", func(t *testing.T) {
		// Volume should exist
		volume := framework.GetVolume(createdPod, framework.AWSTokenVolumeName)
		require.NotNil(t, volume, "aws-token volume should exist")

		// Volume mount should exist
		volumeMount := framework.GetVolumeMount(container, framework.AWSTokenVolumeName)
		require.NotNil(t, volumeMount, "aws-token volume mount should exist")
		assert.Equal(t, framework.AWSTokenMountPath, volumeMount.MountPath)
		assert.True(t, volumeMount.ReadOnly)
	})
}
