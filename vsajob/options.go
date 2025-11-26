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

package vsajob

import (
	"fmt"
	"time"
)

// jobOptions contains Kubernetes Job configuration parameters.
// These control how the VSA generation Job is created and executed.
type jobOptions struct {
	TargetNamespace    string // Namespace where the Job will be created (typically the snapshot's namespace)
	JobName            string // Unique name for the Job (auto-generated with timestamp)
	GeneratorImage     string // Container image for the Conforma CLI
	ServiceAccountName string // Service account for Job pods (needs Secret access)
	CPURequest         string // CPU resource request (Kubernetes quantity format, e.g., "100m")
	MemoryRequest      string // Memory resource request (Kubernetes quantity format, e.g., "256Mi")
	MemoryLimit        string // Memory resource limit (Kubernetes quantity format, e.g., "512Mi")
	BackoffLimit       *int32 // Number of retries before marking Job as failed (nil = use Kubernetes default)
}

// vsaGenerationOptions contains VSA-specific configuration parameters.
// These are passed to the Conforma CLI as command-line arguments.
type vsaGenerationOptions struct {
	PublicKey               string // Public key for verifying image signatures (cosign format)
	VSAUploadURL            string // URL endpoint for uploading VSAs (e.g., Rekor server URL)
	VSASigningKeySecretName string // Name of the Kubernetes Secret containing the VSA signing key
	Workers                 string // Number of concurrent workers for image validation (numeric string)
	Strict                  string // Enable strict mode - fail on any policy violation ("true" or "false")
	IgnoreRekor             string // Skip Rekor transparency log verification ("true" or "false")
	Debug                   string // Enable debug logging in Conforma CLI ("true" or "false")
}

// defaultBackoffLimit is the number of retries for VSA generation Jobs before marking them as failed.
// A value of 2 means the Job will attempt execution up to 3 times total (initial + 2 retries).
var defaultBackoffLimit = int32(2)

// defaultJobOptions creates default Kubernetes Job configuration for a snapshot.
//
// Default values:
//   - TargetNamespace: Uses the snapshot's namespace
//   - JobName: Auto-generated as "vsa-gen-{snapshot-name}-{unix-timestamp}" for uniqueness
//   - GeneratorImage: "quay.io/conforma/cli:latest"
//   - ServiceAccountName: "conforma-vsa-generator"
//   - CPURequest: "100m" (0.1 CPU core)
//   - MemoryRequest: "256Mi"
//   - MemoryLimit: "512Mi"
//   - BackoffLimit: 2 retries
//
// These defaults can be overridden via ConfigMap settings.
func defaultJobOptions(snapshot Snapshot) jobOptions {
	return jobOptions{
		// TODO: Remove this. We're currently overriding the namespace so we always use
		// the namespace where the service runs. If we're doing that then having it here
		// as part of the config makes no sense.
		TargetNamespace:    snapshot.Namespace,
		JobName:            fmt.Sprintf("vsa-gen-%s-%d", snapshot.Name, time.Now().Unix()),
		GeneratorImage:     "quay.io/conforma/cli:latest",
		ServiceAccountName: "conforma-vsa-generator",
		CPURequest:         "100m",
		MemoryRequest:      "256Mi",
		MemoryLimit:        "512Mi",
		BackoffLimit:       &defaultBackoffLimit,
	}
}

// defaultVSAGenerationOptions provides default VSA generation settings.
//
// Default values:
//   - Workers: "1" (single-threaded validation)
//   - Strict: "false" (warnings don't fail the validation)
//   - IgnoreRekor: "false" (verify signatures against Rekor transparency log)
//   - Debug: "false" (normal logging level)
//
// Required fields (PublicKey, VSAUploadURL, VSASigningKeySecretName) must be set via ConfigMap.
var defaultVSAGenerationOptions = vsaGenerationOptions{
	Workers:     "1",
	Strict:      "false",
	IgnoreRekor: "false",
	Debug:       "false",
}
