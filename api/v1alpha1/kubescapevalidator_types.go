/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// KubescapeValidatorSpec defines the desired state of KubescapeValidator
type KubescapeValidatorSpec struct {
	// +kubebuilder:default=kubescape
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	// Global Severity Limit Rule
	SeverityLimitRule SeverityLimitRule `json:"severityLimitRule,omitempty" yaml:"severityLimitRule,omitempty"`
	// Rule for Flagged CVEs
	FlaggedCVERule []FlaggedCVE `json:"flaggedCVERule,omitempty" yaml:"flaggedCVERule,omitempty"`
}

// FlaggedCVE is a flagged CVE rule.
type FlaggedCVE string

// Name returns the formatted name of the flagged CVE.
func (r FlaggedCVE) Name() string {
	return fmt.Sprintf("FLAG-%s", string(r))
}

// ResultCount returns the number of validation results expected for an KubescapeValidatorSpec.
func (s KubescapeValidatorSpec) ResultCount() int {
	count := 0
	if s.SeverityLimitRule != (SeverityLimitRule{}) {
		count++
	}
	count += len(s.FlaggedCVERule)

	return count
}

// SeverityLimitRule verifies that the number of vulnerabilities of each severity level does not
// exceed the specified limit.
type SeverityLimitRule struct {
	Critical   *int `json:"critical,omitempty"`
	High       *int `json:"high,omitempty"`
	Medium     *int `json:"medium,omitempty"`
	Low        *int `json:"low,omitempty"`
	Negligible *int `json:"negligible,omitempty"`
	Unknown    *int `json:"unknown,omitempty"`
}

// Name is the name of all severity limit rules.
func (r SeverityLimitRule) Name() string {
	return "SeverityLimitRule"
}

// KubescapeValidatorStatus defines the observed state of KubescapeValidator
type KubescapeValidatorStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// KubescapeValidator is the Schema for the kubescapevalidators API
type KubescapeValidator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubescapeValidatorSpec   `json:"spec,omitempty"`
	Status KubescapeValidatorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KubescapeValidatorList contains a list of KubescapeValidator
type KubescapeValidatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubescapeValidator `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubescapeValidator{}, &KubescapeValidatorList{})
}
