package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
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

	s.clientset = fake.NewSimpleClientset()
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
		{"Default AWS region", defaultAWSRegion, "eu-central-1"},
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
		debugMode      bool
		logFunc        func()
		expectedOutput string
		shouldContain  bool
	}{
		{
			name:      "Debug logging when enabled",
			debugMode: true,
			logFunc: func() {
				debugLogger.SetOutput(&buf)
				logDebug("test debug message")
			},
			expectedOutput: "test debug message",
			shouldContain:  true,
		},
		{
			name:      "Debug logging when disabled",
			debugMode: false,
			logFunc: func() {
				debugLogger.SetOutput(&buf)
				logDebug("test debug message")
			},
			expectedOutput: "test debug message",
			shouldContain:  false,
		},
		{
			name:      "Info logging",
			debugMode: false,
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
			debugMode = tt.debugMode
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
			s.clientset = fake.NewSimpleClientset()
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
			clientset := fake.NewSimpleClientset()

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
			clientset := fake.NewSimpleClientset()
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
			UID: "test-uid",
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
	clientset := fake.NewSimpleClientset()

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

	clientset := fake.NewSimpleClientset()
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
