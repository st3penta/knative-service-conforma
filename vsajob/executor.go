// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package vsajob provides a library for automating VSA (Verification Summary Attestation)
// generation for Konflux application snapshots using Kubernetes Jobs.
//
// This library integrates with the Konflux ecosystem by discovering EnterpriseContractPolicy
// configurations through ReleasePlan and ReleasePlanAdmission resources, then launching
// Kubernetes Jobs to execute the Conforma CLI for policy verification and VSA generation.
//
// # Quick Start
//
//	import (
//	    "context"
//	    "github.com/conforma/knative-service/vsajob"
//	    "k8s.io/apimachinery/pkg/runtime"
//	    "sigs.k8s.io/controller-runtime/pkg/client"
//	)
//
//	// 1. Register Konflux types with your controller-runtime scheme
//	scheme := runtime.NewScheme()
//	if err := vsajob.AddToScheme(scheme); err != nil {
//	    panic(err)
//	}
//
//	// 2. Create your Kubernetes client with the registered scheme
//	k8sClient, err := client.New(config, client.Options{Scheme: scheme})
//	if err != nil {
//	    panic(err)
//	}
//
//	// 3. Create the executor and configure it
//	executor := vsajob.NewExecutor(k8sClient, logger)
//	executor.WithNamespace("my-service-namespace").WithConfigMapName("vsa-config")
//
//	// 4. Trigger VSA generation for a snapshot
//	snapshot := vsajob.Snapshot{
//	    Name:      "my-app-snapshot-abc123",
//	    Namespace: "my-app-namespace",
//	    Spec:      []byte(`{"application":"my-app","components":[...]}`),
//	}
//	if err := executor.CreateVSAJob(ctx, snapshot); err != nil {
//	    // handle error
//	}
//
// # Configuration
//
// The executor reads its configuration from a Kubernetes ConfigMap in the service's namespace.
// Required ConfigMap fields:
//   - PUBLIC_KEY: Public key for signature verification
//   - VSA_UPLOAD_URL: URL endpoint for uploading generated VSAs (e.g., Rekor)
//   - VSA_SIGNING_KEY_SECRET_NAME: Name of the Kubernetes Secret containing the signing key
//
// Optional ConfigMap fields (with defaults):
//   - GENERATOR_IMAGE: Container image for the Conforma CLI (default: "quay.io/conforma/cli:latest")
//   - SERVICE_ACCOUNT_NAME: Service account for Job pods (default: "conforma-vsa-generator")
//   - CPU_REQUEST: CPU resource request (default: "100m")
//   - MEMORY_REQUEST: Memory resource request (default: "256Mi")
//   - MEMORY_LIMIT: Memory resource limit (default: "512Mi")
//   - BACKOFF_LIMIT: Job retry limit (default: 2)
//   - WORKERS: Concurrent worker count for validation (default: "1")
//   - STRICT: Enable strict validation mode (default: "false")
//   - IGNORE_REKOR: Skip Rekor transparency log verification (default: "false")
//   - DEBUG: Enable debug logging (default: "false")
//
// # Policy Discovery
//
// The library automatically discovers the appropriate EnterpriseContractPolicy for a snapshot
// by following this chain:
//  1. Extract the application name from the snapshot's spec
//  2. Find the ReleasePlan for that application in the snapshot's namespace
//  3. Extract ReleasePlanAdmission reference from ReleasePlan labels
//  4. Retrieve the ReleasePlanAdmission from the target namespace
//  5. Extract the EnterpriseContractPolicy name from the RPA spec
//
// If no ReleasePlan is found, VSA generation is skipped (the snapshot is assumed not releasable).
//
// # RBAC Requirements
//
// The service account used by the executor (in the service's namespace) needs:
//   - get/list permissions for ConfigMaps (to read configuration)
//   - get/list permissions for ReleasePlans (across all relevant namespaces)
//   - get permissions for ReleasePlanAdmissions (across all relevant namespaces)
//   - create permissions for Jobs (in snapshot namespaces)
//
// The service account used by Job pods needs:
//   - get permissions for Secrets (to access the VSA signing key)
//   - network access to the VSA upload URL
package vsajob

//go:generate mockery --name controllerRuntimeClient --structname ControllerRuntimeClient --with-expecter

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// executor implements the Executor interface for VSA generation workflows.
// It orchestrates the creation of Kubernetes Jobs that run the Conforma CLI
// to verify snapshots against enterprise contract policies and generate VSAs.
type executor struct {
	client       controllerRuntimeClient // Kubernetes client for API operations
	logger       logr.Logger             // Structured logger for diagnostic output
	policyFinder policyFinder            // Component for discovering EnterpriseContractPolicy

	namespace     string            // Namespace where the executor's service is running (for ConfigMap lookups)
	configMapName string            // Name of the ConfigMap containing VSA generation configuration
	configMap     *corev1.ConfigMap // Cached ConfigMap to avoid multiple API calls within a single CreateVSAJob execution
}

// NewExecutor creates a new VSA job executor.
//
// IMPORTANT: The provided controller-runtime client must have Konflux custom resource types
// registered in its scheme. You MUST call vsajob.AddToScheme(scheme) before creating the client,
// otherwise the executor will fail to query ReleasePlan and ReleasePlanAdmission resources.
//
// Parameters:
//   - client: A controller-runtime client with Konflux types registered (via AddToScheme)
//   - logger: A logr.Logger instance for structured logging
//
// Returns an Executor with default configuration:
//   - Namespace: "default"
//   - ConfigMap name: "vsa-config"
//
// Use WithNamespace() and WithConfigMapName() to customize these defaults.
//
// Example:
//
//	// 1. Register Konflux types
//	scheme := runtime.NewScheme()
//	_ = clientgoscheme.AddToScheme(scheme)
//	if err := vsajob.AddToScheme(scheme); err != nil {
//	    return fmt.Errorf("failed to register Konflux types: %w", err)
//	}
//
//	// 2. Create client with the scheme
//	k8sClient, err := client.New(config, client.Options{Scheme: scheme})
//	if err != nil {
//	    return fmt.Errorf("failed to create client: %w", err)
//	}
//
//	// 3. Create executor
//	executor := vsajob.NewExecutor(k8sClient, ctrl.Log.WithName("vsa-executor"))
//	executor = executor.WithNamespace(os.Getenv("POD_NAMESPACE")).
//	                   WithConfigMapName("my-vsa-config")
func NewExecutor(
	client controllerRuntimeClient,
	logger logr.Logger,
) Executor {
	return &executor{
		client:        client,
		logger:        logger,
		policyFinder:  newPolicyFinder(client, logger),
		configMapName: "vsa-config",
		namespace:     "default",
	}
}

// WithConfigMapName sets a custom ConfigMap name for reading VSA generation configuration.
//
// The ConfigMap will be read from the namespace specified by WithNamespace() and must contain
// the required fields: PUBLIC_KEY, VSA_UPLOAD_URL, and VSA_SIGNING_KEY_SECRET_NAME.
//
// Default: "vsa-config"
//
// Returns the executor for method chaining.
func (e *executor) WithConfigMapName(configMapName string) Executor {
	e.configMapName = configMapName
	return e
}

// WithNamespace sets the namespace where the executor's service is running.
//
// This namespace is used for:
//   - Reading the ConfigMap (specified by WithConfigMapName)
//   - Determining where to read service configuration
//
// This is NOT the namespace where Jobs will be created - Jobs are created in the
// snapshot's namespace.
//
// Default: "default"
//
// Tip: Use os.Getenv("POD_NAMESPACE") or the Kubernetes downward API to automatically
// detect the service's namespace in production environments.
//
// Returns the executor for method chaining.
func (e *executor) WithNamespace(namespace string) Executor {
	e.namespace = namespace
	return e
}

// CreateVSAJob orchestrates the creation of a Kubernetes Job for VSA generation.
//
// This method implements the core workflow of the Executor interface by coordinating
// configuration loading, policy discovery, and Kubernetes Job creation. It validates
// the snapshot, loads configuration from the ConfigMap, discovers the appropriate
// EnterpriseContractPolicy, and creates a Job to execute the Conforma CLI.
//
// Workflow:
//  1. Validate snapshot name and namespace are present
//  2. Load Kubernetes Job configuration from ConfigMap (with caching)
//  3. Load VSA generation configuration from ConfigMap (with caching)
//  4. Discover EnterpriseContractPolicy via ReleasePlan/ReleasePlanAdmission lookup
//  5. Build Job manifest with all configuration and parameters
//  6. Create the Job in the snapshot's namespace
//
// Parameters:
//   - ctx: Context for Kubernetes API calls (supports cancellation and timeouts)
//   - snapshot: The snapshot to generate VSA for (must have Name, Namespace, and Spec populated)
//
// Returns:
//   - nil on success (Job created successfully)
//   - nil if no ReleasePlan found (snapshot not releasable, VSA generation skipped)
//   - error if validation fails, configuration is invalid, policy discovery fails, or Job creation fails
//
// Special Behaviors:
//   - ConfigMap is loaded once per CreateVSAJob call and cached for subsequent config reads
//   - If no ReleasePlan exists for the snapshot's application, returns nil without creating a Job
//     (this is not an error - it means the snapshot won't be released and doesn't need VSA)
//   - Job is created in the snapshot's namespace, NOT in the executor's service namespace
//   - Job name is auto-generated with timestamp to ensure uniqueness
func (e *executor) CreateVSAJob(ctx context.Context, snapshot Snapshot) error {
	if snapshot.Name == "" {
		return fmt.Errorf("snapshot name is required")
	}

	if snapshot.Namespace == "" {
		return fmt.Errorf("snapshot namespace is required")
	}

	// 1. Read configuration from ConfigMap
	jobOptions, err := e.loadJobOptions(ctx, snapshot)
	if err != nil {
		return fmt.Errorf("failed to read job configuration: %w", err)
	}

	VSAGenerationOptions, err := e.loadVSAGenerationOptions(ctx)
	if err != nil {
		return fmt.Errorf("failed to read VSA generation configuration: %w", err)
	}

	policyConfig, err := e.policyFinder.FindPolicy(ctx, snapshot)
	if err != nil {
		// Only skip VSA generation if no ReleasePlan exists - this is expected behavior
		// for snapshots not intended for release. All other errors should be reported.
		if errors.Is(err, ErrReleasePlanNotFound) {
			e.logger.Info("No ReleasePlan found, skipping VSA generation", "snapshot", snapshot.Name)
			return nil
		}
		return fmt.Errorf("failed to discover policy configuration: %w", err)
	}

	// 3. Create the Job
	job := e.buildJob(snapshot, policyConfig, *jobOptions, *VSAGenerationOptions)

	e.logger.Info("Creating Job", "name", jobOptions.JobName, "namespace", jobOptions.TargetNamespace)
	err = e.client.Create(ctx, job)
	if err != nil {
		return fmt.Errorf("failed to create job %s in namespace %s: %w", jobOptions.JobName, jobOptions.TargetNamespace, err)
	}

	e.logger.Info("Job created successfully", "name", jobOptions.JobName, "namespace", jobOptions.TargetNamespace)
	return nil
}

// loadConfigMap retrieves the VSA configuration ConfigMap from the service's namespace.
// The ConfigMap name and namespace are determined by the executor's configuration
// (set via WithConfigMapName and WithNamespace).
//
// This method uses lazy initialization with caching: on the first call within a CreateVSAJob
// execution, it fetches the ConfigMap from the API and caches it. Subsequent calls within
// the same execution return the cached value, avoiding redundant API calls.
func (e *executor) loadConfigMap(ctx context.Context) (*corev1.ConfigMap, error) {
	// Return cached ConfigMap if already loaded
	if e.configMap != nil {
		return e.configMap, nil
	}

	// Fetch from API on first access
	cm := &corev1.ConfigMap{}
	err := e.client.Get(ctx, client.ObjectKey{
		Namespace: e.namespace,
		Name:      e.configMapName,
	}, cm)
	if err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %s in namespace %s: %w", e.configMapName, e.namespace, err)
	}

	// Cache for subsequent calls
	e.configMap = cm
	return cm, nil
}

// loadJobOptions reads Kubernetes Job configuration from the ConfigMap.
// It starts with sensible defaults and overrides them with ConfigMap values if present.
//
// Configurable fields:
//   - GENERATOR_IMAGE: Container image for the Conforma CLI
//   - SERVICE_ACCOUNT_NAME: Service account for Job pods
//   - CPU_REQUEST, MEMORY_REQUEST, MEMORY_LIMIT: Resource requirements
//   - BACKOFF_LIMIT: Number of retries before marking Job as failed
//
// All resource quantities are validated using Kubernetes resource.ParseQuantity.
func (e *executor) loadJobOptions(ctx context.Context, snapshot Snapshot) (*jobOptions, error) {
	e.logger.Info("Reading k8s job configuration", "configMap", e.configMapName, "namespace", e.namespace)

	cm, cmErr := e.loadConfigMap(ctx)
	if cmErr != nil {
		return nil, cmErr
	}

	opts := defaultJobOptions(snapshot)

	// Run it in the namespace where the service runs regardless of what's in opts
	opts.TargetNamespace = e.namespace

	// Override defaults with ConfigMap values if present
	if v := cm.Data["GENERATOR_IMAGE"]; v != "" {
		opts.GeneratorImage = v
	}
	if v := cm.Data["SERVICE_ACCOUNT_NAME"]; v != "" {
		opts.ServiceAccountName = v
	}
	if v := cm.Data["CPU_REQUEST"]; v != "" {
		if _, err := resource.ParseQuantity(v); err != nil {
			return nil, fmt.Errorf("invalid CPU_REQUEST value %q: %w", v, err)
		}
		opts.CPURequest = v
	}
	if v := cm.Data["MEMORY_REQUEST"]; v != "" {
		if _, err := resource.ParseQuantity(v); err != nil {
			return nil, fmt.Errorf("invalid MEMORY_REQUEST value %q: %w", v, err)
		}
		opts.MemoryRequest = v
	}
	if v := cm.Data["MEMORY_LIMIT"]; v != "" {
		if _, err := resource.ParseQuantity(v); err != nil {
			return nil, fmt.Errorf("invalid MEMORY_LIMIT value %q: %w", v, err)
		}
		opts.MemoryLimit = v
	}
	if v := cm.Data["BACKOFF_LIMIT"]; v != "" {
		backoffQuantity, err := resource.ParseQuantity(v)
		if err != nil {
			return nil, fmt.Errorf("invalid BACKOFF_LIMIT value %q: %w", v, err)
		}
		backoffInt := int32(backoffQuantity.Value()) // #nosec G115 - backoffQuantity is a small config value
		opts.BackoffLimit = &backoffInt
	}

	return &opts, nil
}

// loadVSAGenerationOptions reads VSA-specific configuration from the ConfigMap.
//
// Required fields (will return error if missing):
//   - PUBLIC_KEY: Public key for verifying image signatures
//   - VSA_UPLOAD_URL: Endpoint URL for uploading generated VSAs (typically Rekor)
//   - VSA_SIGNING_KEY_SECRET_NAME: Name of Secret containing the cosign private key
//
// Optional fields (with defaults):
//   - WORKERS: Number of concurrent workers for validation (default: "1")
//   - STRICT: Enable strict validation mode - fail on any policy violation (default: "false")
//   - IGNORE_REKOR: Skip Rekor transparency log verification (default: "false")
//   - DEBUG: Enable debug logging in the Conforma CLI (default: "false")
//
// Boolean fields must be exactly "true" or "false" (case-sensitive).
func (e *executor) loadVSAGenerationOptions(ctx context.Context) (*vsaGenerationOptions, error) {
	e.logger.Info("Reading VSA generation configuration", "configMap", e.configMapName, "namespace", e.namespace)

	cm, cmErr := e.loadConfigMap(ctx)
	if cmErr != nil {
		return nil, cmErr
	}

	// Validate required fields
	publicKey := cm.Data["PUBLIC_KEY"]
	if publicKey == "" {
		return nil, fmt.Errorf("PUBLIC_KEY is required in ConfigMap")
	}
	vsaUploadURL := cm.Data["VSA_UPLOAD_URL"]
	if vsaUploadURL == "" {
		return nil, fmt.Errorf("VSA_UPLOAD_URL is required in ConfigMap")
	}
	signingKeySecretName := cm.Data["VSA_SIGNING_KEY_SECRET_NAME"]
	if signingKeySecretName == "" {
		return nil, fmt.Errorf("VSA_SIGNING_KEY_SECRET_NAME is required in ConfigMap")
	}

	// Start with defaults
	opts := defaultVSAGenerationOptions

	// Set required fields
	opts.PublicKey = publicKey
	opts.VSAUploadURL = vsaUploadURL
	opts.VSASigningKeySecretName = signingKeySecretName

	// Override defaults with ConfigMap values if present
	if v := cm.Data["WORKERS"]; v != "" {
		workersQuantity, err := resource.ParseQuantity(v)
		if err != nil {
			return nil, fmt.Errorf("invalid WORKERS value %q: %w", v, err)
		}
		if workersQuantity.Value() <= 0 {
			return nil, fmt.Errorf("WORKERS must be greater than 0, got %q", v)
		}
		opts.Workers = v
	}
	if v := cm.Data["STRICT"]; v != "" {
		if v != "true" && v != "false" {
			return nil, fmt.Errorf("invalid STRICT value %q: must be 'true' or 'false'", v)
		}
		opts.Strict = v
	}
	if v := cm.Data["IGNORE_REKOR"]; v != "" {
		if v != "true" && v != "false" {
			return nil, fmt.Errorf("invalid IGNORE_REKOR value %q: must be 'true' or 'false'", v)
		}
		opts.IgnoreRekor = v
	}
	if v := cm.Data["DEBUG"]; v != "" {
		if v != "true" && v != "false" {
			return nil, fmt.Errorf("invalid DEBUG value %q: must be 'true' or 'false'", v)
		}
		opts.Debug = v
	}

	return &opts, nil
}

// buildJob constructs a Kubernetes Job manifest for VSA generation.
//
// The Job will:
//   - Run in the snapshot's namespace (not the service's namespace)
//   - Execute the Conforma CLI with the "ec validate image" command
//   - Mount the signing key Secret as a volume at /workspace/signing-key
//   - Use the specified service account (which needs access to the signing key Secret)
//   - Apply resource limits and requests from the configuration
//   - Include labels and annotations for tracking and debugging
//
// The Job name is auto-generated as "vsa-gen-{snapshot-name}-{unix-timestamp}" to ensure uniqueness.
//
// Parameters:
//   - snapshot: The snapshot to generate VSA for
//   - policyConfig: Policy reference in "namespace/name" format (e.g., "rhtap-releng-tenant/registry-standard")
//   - jobOpts: Kubernetes Job configuration (image, resources, service account, etc.)
//   - vsaOpts: VSA generation configuration (keys, upload URL, validation options)
//
// Returns a fully configured Job ready for creation via client.Create().
func (e *executor) buildJob(
	snapshot Snapshot,
	policyConfig string,
	jobOpts jobOptions,
	vsaOpts vsaGenerationOptions,
) *batchv1.Job {
	signingKeyMountPath := "/workspace/signing-key"

	args := []string{
		"validate",
		"image",
		"--images",
		string(snapshot.Spec),
		"--policy",
		policyConfig,
		"--public-key",
		vsaOpts.PublicKey,
		"--ignore-rekor=" + vsaOpts.IgnoreRekor,
		"--strict=" + vsaOpts.Strict,
		"--debug=" + vsaOpts.Debug,
		"--workers",
		vsaOpts.Workers,
		"--output",
		"text",
		"--vsa",
		"--vsa-signing-key",
		// The key filename comes from the Secret data key. When a Secret is mounted as a volume,
		// each key in the Secret's data becomes a file. The Secret must have a data key named "cosign.key".
		signingKeyMountPath + "/cosign.key",
		"--vsa-upload",
		vsaOpts.VSAUploadURL,
		"--show-successes",
	}

	// Build resource requirements
	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	if cpu, err := resource.ParseQuantity(jobOpts.CPURequest); err == nil {
		resources.Requests[corev1.ResourceCPU] = cpu
	}
	if memRequest, err := resource.ParseQuantity(jobOpts.MemoryRequest); err == nil {
		resources.Requests[corev1.ResourceMemory] = memRequest
	}
	if memLimit, err := resource.ParseQuantity(jobOpts.MemoryLimit); err == nil {
		resources.Limits[corev1.ResourceMemory] = memLimit
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobOpts.JobName,
			Namespace: jobOpts.TargetNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "vsa-generator",
				"app.kubernetes.io/instance":   snapshot.Name,
				"app.kubernetes.io/component":  "conforma",
				"app.kubernetes.io/part-of":    "konflux",
				"app.kubernetes.io/managed-by": "conforma-vsajob",
			},
			Annotations: map[string]string{
				"conforma.dev/snapshot-name":      snapshot.Name,
				"conforma.dev/snapshot-namespace": snapshot.Namespace,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: jobOpts.BackoffLimit,

			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":      "vsa-generator",
						"app.kubernetes.io/instance":  snapshot.Name,
						"app.kubernetes.io/component": "conforma",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: jobOpts.ServiceAccountName,
					RestartPolicy:      corev1.RestartPolicyOnFailure,
					Containers: []corev1.Container{
						{
							Name:      "vsa-generator",
							Image:     jobOpts.GeneratorImage,
							Command:   []string{"ec"},
							Args:      args,
							Resources: resources,
							Env: []corev1.EnvVar{
								{
									Name:  "HOME",
									Value: "/tmp",
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "signing-key",
									MountPath: signingKeyMountPath,
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "signing-key",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{SecretName: vsaOpts.VSASigningKeySecretName},
							},
						},
					},
				},
			},
		},
	}
}
