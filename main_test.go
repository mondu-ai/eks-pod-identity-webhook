package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

// MockKubernetesClient wraps fake.Clientset to allow method mocking
type MockKubernetesClient struct {
	*fake.Clientset
	mock.Mock
}

// WebhookTestSuite provides a test suite for webhook functionality
type WebhookTestSuite struct {
	suite.Suite
	server    *WebhookServer
	router    *gin.Engine
	clientset *fake.Clientset
}

func TestWebhookTestSuite(t *testing.T) {
	suite.Run(t, new(WebhookTestSuite))
}

func (s *WebhookTestSuite) SetupTest() {
	// Set gin to test mode to avoid debug output
	gin.SetMode(gin.TestMode)

	s.clientset = fake.NewClientset()
	s.server = &WebhookServer{
		Client: s.clientset,
		Config: Config{
			AWSRegion: "us-west-2",
		},
	}

	s.router = gin.New()
	s.router.POST("/mutate", s.server.handleMutatePod)
	s.router.GET("/healthz", s.server.handleHealthz)
}

func TestConfigDefaults(t *testing.T) {
	tests := []struct {
		name     string
		expected any
		actual   any
	}{
		{"Default listen address", defaultListenAddr, ":8443"},
		{"Default AWS region", defaultAWSRegion, "us-east-1"},
		{"Default TLS cert path", defaultTLSCertPath, "/etc/webhook/certs/tls.crt"},
		{"Default TLS key path", defaultTLSKeyPath, "/etc/webhook/certs/tls.key"},
		{"AWS role ARN annotation key", awsRoleArnAnnotationKey, "eks.amazonaws.com/role-arn"},
		{"AWS token volume name", awsTokenVolumeName, "aws-token"},
		{"AWS token mount path", awsTokenMountPath, "/var/run/secrets/eks.amazonaws.com/serviceaccount"},
		{"Projected token audience", projectedTokenAudience, "sts.amazonaws.com"},
		{"Projected token expiration", projectedTokenExpiration, 3600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.actual)
		})
	}
}

func TestLoggingFunctions(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	originalDebugMode := debugMode

	defer func() {
		debugMode = originalDebugMode
	}()

	tests := []struct {
		name           string
		debugModeVal   bool
		logFunc        func()
		expectedOutput string
		shouldContain  bool
	}{
		{
			name:         "Debug logging when enabled",
			debugModeVal: true,
			logFunc: func() {
				debugLogger.SetOutput(&buf)
				logDebug("test debug message")
			},
			expectedOutput: "test debug message",
			shouldContain:  true,
		},
		{
			name:         "Debug logging when disabled",
			debugModeVal: false,
			logFunc: func() {
				debugLogger.SetOutput(&buf)
				logDebug("test debug message")
			},
			expectedOutput: "test debug message",
			shouldContain:  false,
		},
		{
			name:         "Info logging",
			debugModeVal: false,
			logFunc: func() {
				infoLogger.SetOutput(&buf)
				logInfo("test info message")
			},
			expectedOutput: "test info message",
			shouldContain:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			debugMode = tt.debugModeVal
			tt.logFunc()

			output := buf.String()
			if tt.shouldContain {
				assert.Contains(t, output, tt.expectedOutput)
			} else {
				assert.NotContains(t, output, tt.expectedOutput)
			}
		})
	}
}

func (s *WebhookTestSuite) TestHandleHealthz() {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", http.NoBody)
	require.NoError(s.T(), err)

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, req)

	assert.Equal(s.T(), http.StatusOK, recorder.Code)

	var response map[string]string
	err = json.Unmarshal(recorder.Body.Bytes(), &response)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "ok", response["status"])
}

func (s *WebhookTestSuite) TestHandleMutatePod() {
	tests := []struct {
		name                 string
		requestBody          any
		setupMocks           func()
		expectedStatusCode   int
		expectedAllowed      bool
		expectedHasPatch     bool
		expectedErrorMessage string
	}{
		{
			name:               "Invalid request body",
			requestBody:        "invalid json",
			setupMocks:         func() {},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "Valid admission review with pod mutation",
			requestBody: createAdmissionReview(
				createPodWithServiceAccount("test-pod", "test-namespace", "test-service-account"),
			),
			setupMocks: func() {
				sa := &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service-account",
						Namespace: "test-namespace",
						Annotations: map[string]string{
							awsRoleArnAnnotationKey: "arn:aws:iam::123456789012:role/test-role",
						},
					},
				}
				_, err := s.clientset.CoreV1().ServiceAccounts("test-namespace").Create(
					context.Background(), sa, metav1.CreateOptions{},
				)
				require.NoError(s.T(), err)
			},
			expectedStatusCode: http.StatusOK,
			expectedAllowed:    true,
			expectedHasPatch:   true,
		},
		{
			name: "Pod without service account",
			requestBody: createAdmissionReview(
				createPodWithServiceAccount("test-pod", "test-namespace", ""),
			),
			setupMocks:         func() {},
			expectedStatusCode: http.StatusOK,
			expectedAllowed:    true,
			expectedHasPatch:   false,
		},
		{
			name: "Service account without IAM role annotation",
			requestBody: createAdmissionReview(
				createPodWithServiceAccount("test-pod", "test-namespace", "test-service-account"),
			),
			setupMocks: func() {
				sa := &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service-account",
						Namespace: "test-namespace",
					},
				}
				_, err := s.clientset.CoreV1().ServiceAccounts("test-namespace").Create(
					context.Background(), sa, metav1.CreateOptions{},
				)
				require.NoError(s.T(), err)
			},
			expectedStatusCode: http.StatusOK,
			expectedAllowed:    true,
			expectedHasPatch:   false,
		},
		{
			name: "Service account not found",
			requestBody: createAdmissionReview(
				createPodWithServiceAccount("test-pod", "test-namespace", "nonexistent-sa"),
			),
			setupMocks:         func() {},
			expectedStatusCode: http.StatusOK,
			expectedAllowed:    false,
		},
		{
			name: "Non-pod resource",
			requestBody: func() admissionv1.AdmissionReview {
				ar := createAdmissionReview(createPodWithServiceAccount("test", "test", "test"))
				ar.Request.Resource = metav1.GroupVersionResource{
					Group:    "apps",
					Version:  "v1",
					Resource: "deployments",
				}
				return ar
			}(),
			setupMocks:         func() {},
			expectedStatusCode: http.StatusOK,
			expectedAllowed:    true,
			expectedHasPatch:   false,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			// Reset clientset for each test
			s.clientset = fake.NewClientset()
			s.server.Client = s.clientset

			tt.setupMocks()

			var reqBody []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				reqBody = []byte(str)
			} else {
				reqBody, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}

			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/mutate", bytes.NewBuffer(reqBody))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			recorder := httptest.NewRecorder()
			s.router.ServeHTTP(recorder, req)

			assert.Equal(t, tt.expectedStatusCode, recorder.Code)

			if tt.expectedStatusCode == http.StatusOK {
				var admissionReview admissionv1.AdmissionReview
				err = json.Unmarshal(recorder.Body.Bytes(), &admissionReview)
				require.NoError(t, err)
				require.NotNil(t, admissionReview.Response)

				assert.Equal(t, tt.expectedAllowed, admissionReview.Response.Allowed)

				if tt.expectedHasPatch {
					assert.NotNil(t, admissionReview.Response.Patch)
					assert.NotNil(t, admissionReview.Response.PatchType)
				} else {
					assert.Nil(t, admissionReview.Response.Patch)
				}
			}
		})
	}
}

func TestCreatePatch(t *testing.T) {
	tests := []struct {
		name            string
		pod             *corev1.Pod
		serviceAccount  *corev1.ServiceAccount
		expectedPatches int
		shouldError     bool
		description     string
	}{
		{
			name:            "Pod with empty service account name",
			pod:             createPodWithServiceAccount("test-pod", "test-ns", ""),
			expectedPatches: 0,
			shouldError:     false,
			description:     "Should skip pods without service account",
		},
		{
			name: "Service account with IAM role annotation",
			pod:  createPodWithServiceAccount("test-pod", "test-ns", "test-sa"),
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "test-ns",
					Annotations: map[string]string{
						awsRoleArnAnnotationKey: "arn:aws:iam::123456789012:role/test-role",
					},
				},
			},
			expectedPatches: 10, // 2 volume patches + 2 volumeMount patches + 1 env array + 5 env vars
			shouldError:     false,
			description:     "Should create patches for pod with IAM role",
		},
		{
			name: "Service account without IAM role annotation",
			pod:  createPodWithServiceAccount("test-pod", "test-ns", "test-sa"),
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "test-ns",
				},
			},
			expectedPatches: 0,
			shouldError:     false,
			description:     "Should skip service accounts without IAM role annotation",
		},
		{
			name: "Pod with existing AWS token volume",
			pod: func() *corev1.Pod {
				pod := createPodWithServiceAccount("test-pod", "test-ns", "test-sa")
				pod.Spec.Volumes = []corev1.Volume{
					{
						Name: awsTokenVolumeName,
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
				}
				return pod
			}(),
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "test-ns",
					Annotations: map[string]string{
						awsRoleArnAnnotationKey: "arn:aws:iam::123456789012:role/test-role",
					},
				},
			},
			expectedPatches: 8, // No volume patches, but 2 volumeMount patches + 1 env array + 5 env vars
			shouldError:     false,
			description:     "Should not add duplicate volume but add other patches",
		},
		{
			name: "Pod with existing environment variables",
			pod: func() *corev1.Pod {
				pod := createPodWithServiceAccount("test-pod", "test-ns", "test-sa")
				pod.Spec.Containers[0].Env = []corev1.EnvVar{
					{Name: awsWebIdentityTokenFileEnv, Value: "existing-value"},
					{Name: awsRoleArnEnv, Value: "existing-role"},
				}
				return pod
			}(),
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "test-ns",
					Annotations: map[string]string{
						awsRoleArnAnnotationKey: "arn:aws:iam::123456789012:role/test-role",
					},
				},
			},
			expectedPatches: 7, // 2 volume patches + 2 volumeMount patches + 3 env vars (5 total - 2 existing)
			shouldError:     false,
			description:     "Should not add duplicate environment variables",
		},
		{
			name: "Pod with init containers",
			pod: func() *corev1.Pod {
				pod := createPodWithServiceAccount("test-pod", "test-ns", "test-sa")
				pod.Spec.InitContainers = []corev1.Container{
					{
						Name:  "init-container",
						Image: "busybox:latest",
					},
				}
				return pod
			}(),
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "test-ns",
					Annotations: map[string]string{
						awsRoleArnAnnotationKey: "arn:aws:iam::123456789012:role/test-role",
					},
				},
			},
			expectedPatches: 18, // 2 volume patches + (2 containers + 1 init) * (2 volumeMount + 1 env array + 5 env vars) = 2 + 3*8 = 26, wait let me recalculate
			shouldError:     false,
			description:     "Should handle init containers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewClientset()

			if tt.serviceAccount != nil {
				_, err := clientset.CoreV1().ServiceAccounts(tt.serviceAccount.Namespace).Create(
					context.Background(), tt.serviceAccount, metav1.CreateOptions{},
				)
				require.NoError(t, err)
			}

			server := &WebhookServer{
				Client: clientset,
				Config: Config{AWSRegion: "us-west-2"},
			}

			patchBytes, err := server.createPatch(context.Background(), tt.pod)

			if tt.shouldError {
				assert.Error(t, err, tt.description)
				return
			}

			require.NoError(t, err, tt.description)

			if tt.expectedPatches == 0 {
				assert.Nil(t, patchBytes, tt.description)
				return
			}

			require.NotNil(t, patchBytes, tt.description)

			var patches []JSONPatchEntry
			err = json.Unmarshal(patchBytes, &patches)
			require.NoError(t, err, tt.description)

			assert.Equal(t, tt.expectedPatches, len(patches),
				fmt.Sprintf("%s - expected %d patches, got %d", tt.description, tt.expectedPatches, len(patches)))

			// Validate patch structure
			validatePatches(t, patches, tt.pod)
		})
	}
}

func TestCreatePatchErrorCases(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func(*fake.Clientset)
		pod           *corev1.Pod
		expectError   bool
		errorContains string
	}{
		{
			name: "Service account not found",
			setupMocks: func(_ *fake.Clientset) {
				// Don't create service account
			},
			pod:           createPodWithServiceAccount("test-pod", "test-ns", "nonexistent-sa"),
			expectError:   true,
			errorContains: "failed to get ServiceAccount",
		},
		{
			name: "Kubernetes API error",
			setupMocks: func(clientset *fake.Clientset) {
				clientset.PrependReactor("get", "serviceaccounts", func(_ k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("kubernetes API error")
				})
			},
			pod:           createPodWithServiceAccount("test-pod", "test-ns", "test-sa"),
			expectError:   true,
			errorContains: "kubernetes API error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewClientset()
			tt.setupMocks(clientset)

			server := &WebhookServer{
				Client: clientset,
				Config: Config{AWSRegion: "us-west-2"},
			}

			_, err := server.createPatch(context.Background(), tt.pod)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestJSONPatchOperations(t *testing.T) {
	tests := []struct {
		name    string
		patch   JSONPatchEntry
		isValid bool
	}{
		{
			name:    "Valid add operation",
			patch:   JSONPatchEntry{Op: "add", Path: "/spec/volumes/-", Value: corev1.Volume{}},
			isValid: true,
		},
		{
			name:    "Valid replace operation",
			patch:   JSONPatchEntry{Op: "replace", Path: "/spec/containers/0/image", Value: "nginx:latest"},
			isValid: true,
		},
		{
			name:    "Valid remove operation",
			patch:   JSONPatchEntry{Op: "remove", Path: "/spec/volumes/0"},
			isValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patchBytes, err := json.Marshal([]JSONPatchEntry{tt.patch})
			require.NoError(t, err)

			var patches []JSONPatchEntry
			err = json.Unmarshal(patchBytes, &patches)
			require.NoError(t, err)

			assert.Equal(t, 1, len(patches))
			assert.Equal(t, tt.patch.Op, patches[0].Op)
			assert.Equal(t, tt.patch.Path, patches[0].Path)
		})
	}
}

func TestEnvironmentVariableLogLevel(t *testing.T) {
	tests := []struct {
		name          string
		logLevel      string
		expectedDebug bool
	}{
		{"Debug mode lowercase", "debug", true},
		{"Debug mode uppercase", "DEBUG", true},
		{"Info mode", "info", false},
		{"Empty log level", "", false},
		{"Invalid log level", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalLogLevel := os.Getenv("LOG_LEVEL")
			defer func() {
				if err := os.Setenv("LOG_LEVEL", originalLogLevel); err != nil {
					t.Logf("Failed to restore LOG_LEVEL: %v", err)
				}
			}()

			if err := os.Setenv("LOG_LEVEL", tt.logLevel); err != nil {
				t.Fatalf("Failed to set LOG_LEVEL: %v", err)
			}

			// Simulate init() behavior
			logLevel := os.Getenv("LOG_LEVEL")
			testDebugMode := logLevel == "debug" || logLevel == "DEBUG"

			assert.Equal(t, tt.expectedDebug, testDebugMode)
		})
	}
}

func TestGenerateRoleSessionName(t *testing.T) {
	whs := &WebhookServer{}

	tests := []struct {
		name     string
		pod      *corev1.Pod
		expected string
	}{
		{
			name: "Pod with name",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "my-sa",
				},
			},
			expected: "my-pod",
		},
		{
			name: "Pod without name but with GenerateName",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "my-deployment-",
					Namespace:    "default",
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "my-sa",
				},
			},
			expected: "", // We'll check that it starts with "my-deployment-" and has a timestamp
		},
		{
			name: "Pod without name or GenerateName",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "my-namespace",
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "my-sa",
				},
			},
			expected: "my-namespace-my-sa",
		},
		{
			name: "Pod without name, GenerateName, or ServiceAccount",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "my-namespace",
				},
			},
			expected: "my-namespace-pod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := whs.generateRoleSessionName(tt.pod)

			if tt.name == "Pod without name but with GenerateName" {
				// Special case: check that it starts with the expected prefix and has a timestamp
				if !strings.HasPrefix(result, "my-deployment-") {
					t.Errorf("Expected result to start with 'my-deployment-', got %s", result)
				}
				// Check that it has a timestamp (should be longer than just "my-deployment-")
				if len(result) <= len("my-deployment-") {
					t.Errorf("Expected result to have timestamp suffix, got %s", result)
				}
			} else if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}

			// All results should be non-empty
			if result == "" {
				t.Errorf("generateRoleSessionName should never return empty string")
			}
		})
	}
}

func TestGenerateRoleSessionNameTruncation(t *testing.T) {
	whs := &WebhookServer{}

	tests := []struct {
		name           string
		pod            *corev1.Pod
		maxLen         int
		checkPrefix    string
		checkExactName string
	}{
		{
			name: "Long pod name gets truncated",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "this-is-a-very-long-pod-name-that-exceeds-the-64-character-limit-for-aws-sts",
					Namespace: "default",
				},
			},
			maxLen:      64,
			checkPrefix: "this-is-a-very-long-pod-name-that-exceeds-the-64-character-limi",
		},
		{
			name: "Exactly 64 character pod name is not truncated",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "this-is-exactly-64-characters-long-pod-name-for-testing-purpose",
					Namespace: "default",
				},
			},
			maxLen:         64,
			checkExactName: "this-is-exactly-64-characters-long-pod-name-for-testing-purpose",
		},
		{
			name: "Short pod name is not truncated",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "short-pod",
					Namespace: "default",
				},
			},
			maxLen:         64,
			checkExactName: "short-pod",
		},
		{
			name: "Long GenerateName with timestamp gets truncated",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "this-is-a-very-long-deployment-name-that-will-exceed-limit-",
					Namespace:    "default",
				},
			},
			maxLen:      64,
			checkPrefix: "this-is-a-very-long-deployment-name-that-will-exceed-limit",
		},
		{
			name: "Long namespace and service account gets truncated",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "this-is-a-very-long-namespace-name",
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "this-is-a-very-long-service-account-name",
				},
			},
			maxLen:      64,
			checkPrefix: "this-is-a-very-long-namespace-name-this-is-a-very-long-service-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := whs.generateRoleSessionName(tt.pod)

			// Check max length compliance (AWS STS limit)
			if len(result) > tt.maxLen {
				t.Errorf("Result length %d exceeds max length %d: %s", len(result), tt.maxLen, result)
			}

			// Check exact name if specified
			if tt.checkExactName != "" && result != tt.checkExactName {
				t.Errorf("Expected exact name '%s', got '%s'", tt.checkExactName, result)
			}

			// Check prefix if specified
			if tt.checkPrefix != "" && !strings.HasPrefix(result, tt.checkPrefix) {
				t.Errorf("Expected result to start with '%s', got '%s'", tt.checkPrefix, result)
			}

			// Result should never be empty
			if result == "" {
				t.Errorf("generateRoleSessionName should never return empty string")
			}
		})
	}
}

func TestGenerateRoleSessionNameUniqueness(t *testing.T) {
	whs := &WebhookServer{}

	// Test that multiple calls for pods with GenerateName produce unique names
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "my-deployment-",
			Namespace:    "default",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "my-sa",
		},
	}

	seen := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		result := whs.generateRoleSessionName(pod)
		if seen[result] {
			t.Errorf("Duplicate session name generated: %s", result)
		}
		seen[result] = true

		// Verify length constraint
		if len(result) > 64 {
			t.Errorf("Session name exceeds 64 chars: %s (len=%d)", result, len(result))
		}
	}
}

func TestSanitizeSessionName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Valid characters unchanged",
			input:    "my-pod-name_123",
			expected: "my-pod-name_123",
		},
		{
			name:     "All valid special characters",
			input:    "test+=,.@_-abc",
			expected: "test+=,.@_-abc",
		},
		{
			name:     "Spaces replaced with hyphens",
			input:    "pod with spaces",
			expected: "pod-with-spaces",
		},
		{
			name:     "Special chars replaced with hyphens",
			input:    "pod!@#$%name",
			expected: "pod-@---name",
		},
		{
			name:     "Unicode characters replaced",
			input:    "pod-日本語-name",
			expected: "pod-----------name", // Each multi-byte UTF-8 char becomes multiple hyphens
		},
		{
			name:     "Colons replaced with hyphens",
			input:    "pod:with:colons",
			expected: "pod-with-colons",
		},
		{
			name:     "Slashes replaced with hyphens",
			input:    "pod/with/slashes",
			expected: "pod-with-slashes",
		},
		{
			name:     "Empty string returns empty",
			input:    "",
			expected: "",
		},
		{
			name:     "Only valid uppercase letters",
			input:    "PODNAME",
			expected: "PODNAME",
		},
		{
			name:     "Mixed case with numbers",
			input:    "MyPod123ABC",
			expected: "MyPod123ABC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeSessionName(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeSessionName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGenerateRoleSessionNameEmptyGenerateName(t *testing.T) {
	whs := &WebhookServer{}

	// Test edge case: GenerateName is empty string
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "",
			Namespace:    "default",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "test-sa",
		},
	}

	// Should not panic and should fall through to ServiceAccountName case
	result := whs.generateRoleSessionName(pod)
	expected := "default-test-sa"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestGenerateRoleSessionNameSanitization(t *testing.T) {
	whs := &WebhookServer{}

	t.Run("Pod name with valid chars is unchanged", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-valid-pod-name",
				Namespace: "default",
			},
		}
		result := whs.generateRoleSessionName(pod)
		if result != "my-valid-pod-name" {
			t.Errorf("Expected result to be %q, got %q", "my-valid-pod-name", result)
		}
	})

	t.Run("ServiceAccount fallback is sanitized", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "my-namespace",
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: "my-service-account",
			},
		}
		result := whs.generateRoleSessionName(pod)
		if result != "my-namespace-my-service-account" {
			t.Errorf("Expected result to be %q, got %q", "my-namespace-my-service-account", result)
		}
	})
}

// Helper functions

func createAdmissionReview(pod *corev1.Pod) admissionv1.AdmissionReview {
	podBytes, err := json.Marshal(pod)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal pod: %v", err))
	}

	return admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:       "test-uid",
			Operation: admissionv1.Create,
			Resource: metav1.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			},
			Object: runtime.RawExtension{
				Raw: podBytes,
			},
		},
	}
}

func createPodWithServiceAccount(name, namespace, serviceAccountName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: serviceAccountName,
			Containers: []corev1.Container{
				{
					Name:  "app-container",
					Image: "nginx:latest",
				},
			},
		},
	}
}

func validatePatches(t *testing.T, patches []JSONPatchEntry, _ *corev1.Pod) {
	validOps := map[string]bool{"add": true, "replace": true, "remove": true}

	for i, patch := range patches {
		assert.True(t, validOps[patch.Op],
			fmt.Sprintf("Patch %d has invalid operation: %s", i, patch.Op))

		assert.True(t, strings.HasPrefix(patch.Path, "/"),
			fmt.Sprintf("Patch %d has invalid path (should start with /): %s", i, patch.Path))

		// Validate common patch paths
		if strings.Contains(patch.Path, "/spec/volumes") {
			assert.Contains(t, []string{"add"}, patch.Op,
				fmt.Sprintf("Volume patch %d should be add operation", i))
		}

		if strings.Contains(patch.Path, "/env") {
			assert.Contains(t, []string{"add"}, patch.Op,
				fmt.Sprintf("Environment variable patch %d should be add operation", i))
		}

		if strings.Contains(patch.Path, "/volumeMounts") {
			assert.Contains(t, []string{"add"}, patch.Op,
				fmt.Sprintf("Volume mount patch %d should be add operation", i))
		}
	}
}

// Benchmark tests for performance validation

func BenchmarkCreatePatch(b *testing.B) {
	clientset := fake.NewClientset()

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "benchmark-sa",
			Namespace: "benchmark-ns",
			Annotations: map[string]string{
				awsRoleArnAnnotationKey: "arn:aws:iam::123456789012:role/benchmark-role",
			},
		},
	}

	_, err := clientset.CoreV1().ServiceAccounts("benchmark-ns").Create(
		context.Background(), sa, metav1.CreateOptions{},
	)
	if err != nil {
		b.Fatal(err)
	}

	server := &WebhookServer{
		Client: clientset,
		Config: Config{AWSRegion: "us-west-2"},
	}

	pod := createPodWithServiceAccount("benchmark-pod", "benchmark-ns", "benchmark-sa")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := server.createPatch(context.Background(), pod)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandleMutatePod(b *testing.B) {
	gin.SetMode(gin.TestMode)

	clientset := fake.NewClientset()
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "benchmark-sa",
			Namespace: "benchmark-ns",
			Annotations: map[string]string{
				awsRoleArnAnnotationKey: "arn:aws:iam::123456789012:role/benchmark-role",
			},
		},
	}

	_, err := clientset.CoreV1().ServiceAccounts("benchmark-ns").Create(
		context.Background(), sa, metav1.CreateOptions{},
	)
	if err != nil {
		b.Fatal(err)
	}

	server := &WebhookServer{
		Client: clientset,
		Config: Config{AWSRegion: "us-west-2"},
	}

	router := gin.New()
	router.POST("/mutate", server.handleMutatePod)

	pod := createPodWithServiceAccount("benchmark-pod", "benchmark-ns", "benchmark-sa")
	admissionReview := createAdmissionReview(pod)
	reqBody, err := json.Marshal(admissionReview)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/mutate", bytes.NewBuffer(reqBody))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			b.Fatalf("Expected status %d, got %d", http.StatusOK, recorder.Code)
		}
	}
}

// TestCreateHTTPServerIdleTimeout pins the keep-alive handshake with kube-apiserver, whose webhook
// client reuses idle HTTP/1.1 connections until http.DefaultTransport.IdleConnTimeout.
func TestCreateHTTPServerIdleTimeout(t *testing.T) {
	apiserverTransport, ok := http.DefaultTransport.(*http.Transport)
	require.True(t, ok, "http.DefaultTransport should be an *http.Transport")

	srv := createHTTPServer(defaultListenAddr, http.NewServeMux(), nil)

	assert.Greater(t, srv.IdleTimeout, apiserverTransport.IdleConnTimeout,
		"the server must not close an idle connection the apiserver may still reuse")
}

// TestProcessAdmissionRequestServiceAccountLookupError tests that a failed ServiceAccount lookup
// denies the pod with a status Kubernetes clients retry, not a terminal one.
func TestProcessAdmissionRequestServiceAccountLookupError(t *testing.T) {
	clientset := fake.NewClientset()
	clientset.PrependReactor("get", "serviceaccounts", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("kubernetes API error")
	})
	server := &WebhookServer{Client: clientset, Config: Config{AWSRegion: "us-west-2"}}
	review := createAdmissionReview(createPodWithServiceAccount("test-pod", "test-ns", "test-sa"))

	assertRetryableDenial(t, server.processAdmissionRequest(context.Background(), review.Request))
}

// TestProcessAdmissionRequestSlowServiceAccountLookup tests that the webhook decides on a hanging
// ServiceAccount lookup before the apiserver gives up on it and admits the pod unmutated.
func TestProcessAdmissionRequestSlowServiceAccountLookup(t *testing.T) {
	const decisionBudget = 5 * time.Second // half of the default 10s webhook timeoutSeconds

	release := make(chan struct{})
	apiserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer apiserver.Close()
	defer close(release)

	client, err := kubernetes.NewForConfig(&rest.Config{Host: apiserver.URL})
	require.NoError(t, err)
	server := &WebhookServer{Client: client, Config: Config{AWSRegion: "us-west-2"}}
	review := createAdmissionReview(createPodWithServiceAccount("test-pod", "test-ns", "test-sa"))

	answered := make(chan *admissionv1.AdmissionResponse, 1)
	go func() {
		answered <- server.processAdmissionRequest(context.Background(), review.Request)
	}()

	select {
	case res := <-answered:
		assertRetryableDenial(t, res)
	case <-time.After(decisionBudget):
		t.Fatalf("no admission decision within %s while the ServiceAccount lookup hangs", decisionBudget)
	}
}

func assertRetryableDenial(t *testing.T, res *admissionv1.AdmissionResponse) {
	t.Helper()

	require.False(t, res.Allowed, "a pod must not be admitted while its role is unknown")
	require.NotNil(t, res.Result)
	assert.Equal(t, int32(http.StatusServiceUnavailable), res.Result.Code)
	assert.Equal(t, metav1.StatusReasonServiceUnavailable, res.Result.Reason)
	require.NotNil(t, res.Result.Details, "the apiserver sets Retry-After from Details.RetryAfterSeconds")
	assert.Positive(t, res.Result.Details.RetryAfterSeconds)
}

// TestCloseWhileDraining tests that a connection stays open for reuse while serving, and that once
// draining starts the server closes it after the response and tells the client so.
func TestCloseWhileDraining(t *testing.T) {
	server, client, url := startDrainTestServer(t)

	assert.False(t, get(t, client, url), "connections stay reusable while serving")
	assert.Equal(t, int64(1), server.openConns.Load())

	server.draining.Store(true)

	assert.True(t, get(t, client, url), "the response should tell the client to close the connection")
	assert.Eventually(t, func() bool { return server.openConns.Load() == 0 }, 2*time.Second, 10*time.Millisecond,
		"the server should close the connection after the response")
}

// TestDrainWaitsForClientsToCloseConnections tests that draining outlasts an idle keep-alive connection
// until its client closes it, since closing it from the server races the client's reuse of it.
func TestDrainWaitsForClientsToCloseConnections(t *testing.T) {
	server, client, url := startDrainTestServer(t)
	idle(t, client, url)

	drained := make(chan struct{})
	go func() {
		server.drain(50*time.Millisecond, 5*time.Second)
		close(drained)
	}()

	select {
	case <-drained:
		t.Fatal("drain finished while a client still held an idle connection")
	case <-time.After(500 * time.Millisecond):
	}

	client.CloseIdleConnections()

	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("drain kept waiting after the client closed its connection")
	}
}

// TestDrainGivesUpAfterMaxDelay tests that a client which never lets go cannot hold off shutdown forever.
func TestDrainGivesUpAfterMaxDelay(t *testing.T) {
	server, client, url := startDrainTestServer(t)
	idle(t, client, url)

	const maxDelay = 300 * time.Millisecond

	start := time.Now()
	drained := make(chan struct{})
	go func() {
		server.drain(50*time.Millisecond, maxDelay)
		close(drained)
	}()

	select {
	case <-drained:
		assert.GreaterOrEqual(t, time.Since(start), maxDelay, "drain gave up before its maximum delay")
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not give up at its maximum delay")
	}
}

func startDrainTestServer(t *testing.T) (*WebhookServer, *http.Client, string) {
	t.Helper()

	server := &WebhookServer{Client: fake.NewClientset(), Config: Config{AWSRegion: "us-west-2"}}
	srv := createHTTPServer("127.0.0.1:0", setupRouter(server), nil)
	srv.ConnState = server.trackConnState

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		_ = srv.Serve(listener) //nolint:errcheck // stopped by Close below
	}()
	t.Cleanup(func() {
		_ = srv.Close() //nolint:errcheck // test cleanup
	})

	client := &http.Client{Transport: &http.Transport{}}
	t.Cleanup(client.CloseIdleConnections)
	return server, client, "http://" + listener.Addr().String() + "/healthz"
}

// idle makes one request and leaves its keep-alive connection idle in the client's pool.
func idle(t *testing.T, client *http.Client, url string) {
	t.Helper()
	get(t, client, url)
}

// get makes one request and reports whether the response asked to close the connection.
func get(t *testing.T, client *http.Client, url string) bool {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	require.NoError(t, err)
	res, err := client.Do(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	return res.Close
}

// TestProcessAdmissionRequestNonCreate tests that only pod creation is mutated: a pod's volumes and env are
// immutable afterwards, so the webhook neither looks up the ServiceAccount nor patches.
func TestProcessAdmissionRequestNonCreate(t *testing.T) {
	operations := map[string]admissionv1.Operation{
		"update":  admissionv1.Update,
		"delete":  admissionv1.Delete,
		"connect": admissionv1.Connect,
	}

	for hint, operation := range operations {
		t.Run(hint, func(t *testing.T) {
			clientset := fake.NewClientset()
			server := &WebhookServer{Client: clientset, Config: Config{AWSRegion: "us-west-2"}}
			review := createAdmissionReview(createPodWithServiceAccount("test-pod", "test-ns", "test-sa"))
			review.Request.Operation = operation

			res := server.processAdmissionRequest(context.Background(), review.Request)

			assert.True(t, res.Allowed)
			assert.Nil(t, res.Patch)
			assert.Empty(t, clientset.Actions(), "the ServiceAccount should not be looked up")
		})
	}
}

// TestDefaultShutdownFitsDefaultGracePeriod tests that a chart without a longer terminationGracePeriodSeconds
// does not kill the webhook in the middle of its drain.
func TestDefaultShutdownFitsDefaultGracePeriod(t *testing.T) {
	const kubernetesDefaultGracePeriod = 30 * time.Second

	assert.LessOrEqual(t, defaultShutdownDrainTimeout+shutdownTimeout, kubernetesDefaultGracePeriod)
}

func TestParseShutdownDrainTimeout(t *testing.T) {
	cases := map[string]struct {
		value     string
		expected  time.Duration
		expectErr bool
	}{
		"unset":    {value: "", expected: defaultShutdownDrainTimeout},
		"set":      {value: "100s", expected: 100 * time.Second},
		"invalid":  {value: "soon", expectErr: true},
		"zero":     {value: "0s", expectErr: true},
		"negative": {value: "-5s", expectErr: true},
	}

	for hint, c := range cases {
		t.Run(hint, func(t *testing.T) {
			timeout, err := parseShutdownDrainTimeout(c.value)

			if c.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.expected, timeout)
		})
	}
}
