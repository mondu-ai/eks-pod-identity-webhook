package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	Version = "dev"
	scheme  = runtime.NewScheme()
	codecs  = serializer.NewCodecFactory(scheme)

	// Standard loggers for different levels
	infoLogger  *log.Logger
	warnLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
	debugMode   bool
)

// Config holds the webhook configuration
type Config struct {
	TLSCertPath string
	TLSKeyPath  string
	ListenAddr  string
	AWSRegion   string
}

// WebhookServer holds the dependencies for the webhook server
type WebhookServer struct {
	Client kubernetes.Interface
	Config Config
}

const (
	defaultListenAddr          = ":8443"
	defaultAWSRegion           = "eu-central-1"
	defaultTLSCertPath         = "/etc/webhook/certs/tls.crt"
	defaultTLSKeyPath          = "/etc/webhook/certs/tls.key"
	awsRoleArnAnnotationKey    = "eks.amazonaws.com/role-arn"
	awsTokenVolumeName         = "aws-token"
	awsTokenMountPath          = "/var/run/secrets/eks.amazonaws.com/serviceaccount" // #nosec G101 - Standard path, not a secret
	awsTokenPath               = "token"
	awsWebIdentityTokenFileEnv = "AWS_WEB_IDENTITY_TOKEN_FILE" // #nosec G101 - Standard env var name, not a secret
	awsRoleArnEnv              = "AWS_ROLE_ARN"
	awsRegionEnv               = "AWS_REGION"
	awsDefaultRegionEnv        = "AWS_DEFAULT_REGION"
	awsRoleSessionNameEnv      = "AWS_ROLE_SESSION_NAME"
	projectedTokenAudience     = "sts.amazonaws.com" // #nosec G101 - Standard audience, not a secret
	projectedTokenExpiration   = 3600
	readHeaderTimeout          = 15 * time.Second
)

type JSONPatchEntry struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(scheme)
	_ = admissionv1.AddToScheme(scheme)

	// Initialize loggers with appropriate prefixes and flags
	logFlags := log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile

	infoLogger = log.New(os.Stdout, "INFO: ", logFlags)
	warnLogger = log.New(os.Stdout, "WARN: ", logFlags)
	errorLogger = log.New(os.Stderr, "ERROR: ", logFlags)
	debugLogger = log.New(os.Stdout, "DEBUG: ", logFlags)

	// Check if debug mode is enabled
	logLevel := os.Getenv("LOG_LEVEL")
	debugMode = logLevel == "debug" || logLevel == "DEBUG"

	if debugMode {
		debugLogger.Println("Debug logging enabled")
	}
}

// Logging helper functions following Go best practices
func logInfo(v ...any) {
	infoLogger.Println(v...)
}

func logInfof(format string, v ...any) {
	infoLogger.Printf(format, v...)
}

func logWarn(v ...any) {
	warnLogger.Println(v...)
}

func logWarnf(format string, v ...any) {
	warnLogger.Printf(format, v...)
}

func logError(v ...any) {
	errorLogger.Println(v...)
}

func logErrorf(format string, v ...any) {
	errorLogger.Printf(format, v...)
}

func logDebug(v ...any) {
	if debugMode {
		debugLogger.Println(v...)
	}
}

func logDebugf(format string, v ...any) {
	if debugMode {
		debugLogger.Printf(format, v...)
	}
}

func logFatalf(format string, v ...any) {
	errorLogger.Printf(format, v...)
	os.Exit(1)
}

func main() {
	cfg := parseConfig()
	kubeConfig := setupKubernetesConfig()
	clientset := createKubernetesClient(kubeConfig)

	webhookServer := &WebhookServer{
		Client: clientset,
		Config: cfg,
	}

	router := setupRouter(webhookServer)
	server := createHTTPServer(cfg.ListenAddr, router)

	startServer(server, cfg)
}

func parseConfig() Config {
	cfg := Config{}
	flag.StringVar(&cfg.TLSCertPath, "tls-cert-path", defaultTLSCertPath, "Path to the TLS certificate file.")
	flag.StringVar(&cfg.TLSKeyPath, "tls-key-path", defaultTLSKeyPath, "Path to the TLS private key file.")
	flag.StringVar(&cfg.ListenAddr, "listen-addr", defaultListenAddr, "Address for the webhook server to listen on.")
	flag.StringVar(&cfg.AWSRegion, "aws-region", defaultAWSRegion, "Default AWS region for injected pods.")
	flag.Parse()

	logInfof("Starting EKS IAM Pod Identity Webhook version %s", Version)
	logInfof("Loaded configuration: listen_addr=%s, aws_region=%s, tls_cert_path=%s, tls_key_path=%s, env=%s",
		cfg.ListenAddr, cfg.AWSRegion, cfg.TLSCertPath, cfg.TLSKeyPath, os.Getenv("ENV"))

	return cfg
}

func setupKubernetesConfig() *rest.Config {
	var kubeConfig *rest.Config
	var err error

	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath != "" {
		logInfof("Attempting to load kubeconfig from KUBECONFIG environment variable: %s", kubeconfigPath)
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}

	if err != nil || kubeconfigPath == "" {
		if kubeconfigPath == "" {
			logInfo("KUBECONFIG environment variable not set or empty.")
		} else {
			logWarnf("Failed to load kubeconfig from KUBECONFIG path. Falling back to in-cluster config. Error: %v", err)
		}
		kubeConfig, err = rest.InClusterConfig()
		if err != nil {
			logFatalf("Failed to load in-cluster kubeconfig: %v", err)
		}
		logInfo("Successfully loaded in-cluster kubeconfig")
	} else {
		logInfo("Successfully loaded kubeconfig from KUBECONFIG environment variable")
	}

	return kubeConfig
}

func createKubernetesClient(kubeConfig *rest.Config) kubernetes.Interface {
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		logFatalf("Failed to create Kubernetes clientset: %v", err)
	}
	return clientset
}

func setupRouter(webhookServer *WebhookServer) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery()) // Gin's recovery middleware will handle panics
	router.Use(loggingMiddleware())

	router.POST("/mutate", webhookServer.handleMutatePod)
	router.GET("/healthz", webhookServer.handleHealthz)

	return router
}

func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery

		c.Next() // Process request

		// Skip logging for successful health checks
		if path == "/healthz" && c.Writer.Status() == http.StatusOK {
			return
		}

		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

		if rawQuery != "" {
			path = path + "?" + rawQuery
		}

		logMessage := fmt.Sprintf("method=%s path=%s status_code=%d latency=%s client_ip=%s", method, path, statusCode, latency, clientIP)
		if errorMessage != "" {
			logMessage = fmt.Sprintf("%s error='%s'", logMessage, errorMessage)
		}

		switch {
		case statusCode >= http.StatusInternalServerError:
			logError(logMessage)
		case statusCode >= http.StatusBadRequest:
			logWarn(logMessage)
		default:
			logInfo(logMessage)
		}
	}
}

func createHTTPServer(listenAddr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}
}

func startServer(srv *http.Server, cfg Config) {
	logInfof("Server listening on %s", cfg.ListenAddr)

	go func() {
		if err := srv.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil && err != http.ErrServerClosed {
			logFatalf("Failed to start HTTPS server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logInfo("Shutting down server...")

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctxShutdown); err != nil {
		logErrorf("Server forced to shutdown: %v", err)
	}

	logInfo("Server exiting")
}

func (whs *WebhookServer) handleHealthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (whs *WebhookServer) handleMutatePod(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logErrorf("Failed to read request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not read request body"})
		return
	}
	defer c.Request.Body.Close()

	admissionReview, err := whs.parseAdmissionReview(body)
	if err != nil {
		logErrorf("Failed to parse AdmissionReview: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response := whs.processAdmissionRequest(c.Request.Context(), admissionReview.Request)
	finalAdmissionReview := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{Kind: "AdmissionReview", APIVersion: "admission.k8s.io/v1"},
		Response: response,
	}
	c.JSON(http.StatusOK, finalAdmissionReview)
}

func (whs *WebhookServer) parseAdmissionReview(body []byte) (*admissionv1.AdmissionReview, error) {
	var admissionReview admissionv1.AdmissionReview
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(body, nil, &admissionReview); err != nil {
		return nil, fmt.Errorf("could not decode AdmissionReview: %w", err)
	}

	if admissionReview.Request == nil {
		return nil, fmt.Errorf("AdmissionReview request is nil")
	}

	return &admissionReview, nil
}

func (whs *WebhookServer) processAdmissionRequest(ctx context.Context, request *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	admissionResponse := &admissionv1.AdmissionResponse{
		UID:     request.UID,
		Allowed: true,
	}

	if !whs.isValidPodResource(request) {
		logWarnf("Unexpected resource type %s, expected pods. Allowing without mutation.", request.Resource.Resource)
		return admissionResponse
	}

	pod, err := whs.deserializePod(request.Object.Raw)
	if err != nil {
		logErrorf("Failed to deserialize Pod: %v", err)
		admissionResponse.Allowed = false
		admissionResponse.Result = &metav1.Status{Message: err.Error(), Code: http.StatusInternalServerError}
		return admissionResponse
	}

	logInfof("Handling mutation for Pod: %s/%s (SA: %s)", pod.Namespace, pod.Name, pod.Spec.ServiceAccountName)
	return whs.createMutationResponse(ctx, pod, admissionResponse)
}

func (whs *WebhookServer) isValidPodResource(request *admissionv1.AdmissionRequest) bool {
	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	return request.Resource == podResource
}

func (whs *WebhookServer) deserializePod(raw []byte) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, pod); err != nil {
		return nil, err
	}
	return pod, nil
}

func (whs *WebhookServer) createMutationResponse(ctx context.Context, pod *corev1.Pod, response *admissionv1.AdmissionResponse) *admissionv1.AdmissionResponse {
	patchBytes, err := whs.createPatch(ctx, pod)
	if err != nil {
		logErrorf("Failed to create patch for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		response.Allowed = false
		response.Result = &metav1.Status{Message: fmt.Sprintf("Failed to create patch: %v", err), Code: http.StatusInternalServerError}
		return response
	}

	if len(patchBytes) > 0 {
		response.Patch = patchBytes
		patchType := admissionv1.PatchTypeJSONPatch
		response.PatchType = &patchType
		logInfof("Pod mutation patch generated for %s/%s", pod.Namespace, pod.Name)
	} else {
		logInfof("No mutation needed for pod %s/%s", pod.Namespace, pod.Name)
	}

	return response
}

func (whs *WebhookServer) createPatch(ctx context.Context, pod *corev1.Pod) ([]byte, error) {
	if pod.Spec.ServiceAccountName == "" {
		logDebugf("Pod %s/%s has no service account name, skipping.", pod.Namespace, pod.Name)
		return nil, nil
	}

	roleArn, err := whs.getRoleArnFromServiceAccount(ctx, pod)
	if err != nil {
		return nil, err
	}
	if roleArn == "" {
		return nil, nil // No role ARN found, skip mutation
	}

	logInfof("Using AWS role ARN %s for mutation of pod %s/%s", roleArn, pod.Namespace, pod.Name)

	var patches []JSONPatchEntry

	// Add volume patches
	volumePatches := whs.createVolumePatches(pod)
	patches = append(patches, volumePatches...)

	// Add container patches
	containerPatches := whs.createContainerPatches(pod, roleArn)
	patches = append(patches, containerPatches...)

	if len(patches) == 0 {
		return nil, nil
	}
	return json.Marshal(patches)
}

func (whs *WebhookServer) getRoleArnFromServiceAccount(ctx context.Context, pod *corev1.Pod) (string, error) {
	sa, err := whs.Client.CoreV1().ServiceAccounts(pod.Namespace).Get(ctx, pod.Spec.ServiceAccountName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get ServiceAccount %s/%s: %w", pod.Namespace, pod.Spec.ServiceAccountName, err)
	}

	roleArn, ok := sa.Annotations[awsRoleArnAnnotationKey]
	if !ok {
		logInfof("ServiceAccount %s/%s in namespace %s does not have '%s' annotation, skipping.", sa.Name, pod.Name, pod.Namespace, awsRoleArnAnnotationKey)
		return "", nil
	}

	return roleArn, nil
}

func (whs *WebhookServer) createVolumePatches(pod *corev1.Pod) []JSONPatchEntry {
	var patches []JSONPatchEntry

	// Check if volume already exists
	volumeExists := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == awsTokenVolumeName {
			volumeExists = true
			break
		}
	}

	if volumeExists {
		logWarnf("Volume '%s' already exists in pod %s/%s, not adding.", awsTokenVolumeName, pod.Namespace, pod.Name)
		return patches
	}

	volume := corev1.Volume{
		Name: awsTokenVolumeName,
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{
					{
						ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
							Audience:          projectedTokenAudience,
							ExpirationSeconds: func() *int64 { i := int64(projectedTokenExpiration); return &i }(),
							Path:              awsTokenPath,
						},
					},
				},
			},
		},
	}

	volumePath := "/spec/volumes"
	if pod.Spec.Volumes == nil {
		patches = append(patches, JSONPatchEntry{Op: "add", Path: volumePath, Value: []corev1.Volume{}})
	}
	patches = append(patches, JSONPatchEntry{
		Op:    "add",
		Path:  volumePath + "/-",
		Value: volume,
	})

	return patches
}

func (whs *WebhookServer) createContainerPatches(pod *corev1.Pod, roleArn string) []JSONPatchEntry {
	var patches []JSONPatchEntry

	initContainerPatches := whs.addMutationsToContainers(pod.Spec.InitContainers, "initContainer", "/spec/initContainers", roleArn, pod)
	patches = append(patches, initContainerPatches...)

	containerPatches := whs.addMutationsToContainers(pod.Spec.Containers, "container", "/spec/containers", roleArn, pod)
	patches = append(patches, containerPatches...)

	return patches
}

func (whs *WebhookServer) addMutationsToContainers(containers []corev1.Container, containerType string, basePath string, roleArn string, pod *corev1.Pod) []JSONPatchEntry {
	var containerPatches []JSONPatchEntry

	for i, container := range containers {
		currentContainerPath := fmt.Sprintf("%s/%d", basePath, i)

		// Add volume mount patches
		vmPatches := whs.createVolumeMountPatches(container, currentContainerPath, containerType, pod)
		containerPatches = append(containerPatches, vmPatches...)

		// Add environment variable patches
		envPatches := whs.createEnvironmentPatches(container, currentContainerPath, containerType, roleArn, pod)
		containerPatches = append(containerPatches, envPatches...)

		logDebugf("Finished mutations for %s %s for pod %s/%s", containerType, container.Name, pod.Namespace, pod.Name)
	}

	return containerPatches
}

func (whs *WebhookServer) createVolumeMountPatches(container corev1.Container, containerPath string, containerType string, pod *corev1.Pod) []JSONPatchEntry {
	var patches []JSONPatchEntry

	// Check if volume mount already exists
	vmExists := false
	for _, vm := range container.VolumeMounts {
		if vm.Name == awsTokenVolumeName {
			vmExists = true
			logDebugf("VolumeMount '%s' already exists in %s %s for pod %s/%s.", awsTokenVolumeName, containerType, container.Name, pod.Namespace, pod.Name)
			break
		}
	}

	if vmExists {
		return patches
	}

	vmMountPath := containerPath + "/volumeMounts"
	if container.VolumeMounts == nil {
		patches = append(patches, JSONPatchEntry{Op: "add", Path: vmMountPath, Value: []corev1.VolumeMount{}})
	}
	patches = append(patches, JSONPatchEntry{
		Op:   "add",
		Path: vmMountPath + "/-",
		Value: corev1.VolumeMount{
			Name:      awsTokenVolumeName,
			MountPath: awsTokenMountPath,
			ReadOnly:  true,
		},
	})
	logDebugf("Added VolumeMount '%s' to %s %s for pod %s/%s.", awsTokenVolumeName, containerType, container.Name, pod.Namespace, pod.Name)

	return patches
}

func (whs *WebhookServer) createEnvironmentPatches(container corev1.Container, containerPath string, containerType string, roleArn string, pod *corev1.Pod) []JSONPatchEntry {
	var patches []JSONPatchEntry

	envVarsToAdd := []corev1.EnvVar{
		{Name: awsWebIdentityTokenFileEnv, Value: fmt.Sprintf("%s/%s", awsTokenMountPath, awsTokenPath)},
		{Name: awsRoleArnEnv, Value: roleArn},
		{Name: awsRegionEnv, Value: whs.Config.AWSRegion},
		{Name: awsDefaultRegionEnv, Value: whs.Config.AWSRegion},
		{Name: awsRoleSessionNameEnv, Value: pod.Name},
	}

	envPath := containerPath + "/env"
	if container.Env == nil && len(envVarsToAdd) > 0 {
		patches = append(patches, JSONPatchEntry{Op: "add", Path: envPath, Value: []corev1.EnvVar{}})
	}

	for _, newEnvVar := range envVarsToAdd {
		envExists := false
		for _, existingEnvVar := range container.Env {
			if existingEnvVar.Name == newEnvVar.Name {
				envExists = true
				logDebugf("EnvVar '%s' already exists in %s %s for pod %s/%s.", newEnvVar.Name, containerType, container.Name, pod.Namespace, pod.Name)
				break
			}
		}
		if !envExists {
			patches = append(patches, JSONPatchEntry{
				Op:    "add",
				Path:  envPath + "/-",
				Value: newEnvVar,
			})
			logDebugf("Added EnvVar '%s' to %s %s for pod %s/%s.", newEnvVar.Name, containerType, container.Name, pod.Namespace, pod.Name)
		}
	}

	return patches
}
