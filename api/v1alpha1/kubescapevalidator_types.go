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
	//+kubebuilder:default=kubescape
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	// global ignored CVEs
	IgnoredCVEs []IgnoredCVE `json:"ignoredCVEs,omitempty" yaml:"ignoredCVERule,omitempty"`
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="KubescapeRules must have a unique RuleName",rule="self.all(e, size(self.filter(x, x.name == e.name)) == 1)"
	SeverityLimitRules []SeverityLimitRule `json:"kubescapeRules,omitempty" yaml:"kubescapeRules,omitempty"`

	FlaggedCVERules []FlaggedCVE `json:"flaggedCVEs,omitempty" yaml:"flaggedCVERule,omitempty"`
}

type SeverityLimitRule struct {
	// Global Severity Limit Rule
	SeverityLimits SeverityLimits `json:"severityLimitRule,omitempty" yaml:"severityLimitRule,omitempty"`
	// Global Ignore CVEs
	IgnoredCVEs []IgnoredCVE `json:"ignoredCVEs,omitempty" yaml:"ignoredCVERule,omitempty"`
	// Rule for Flagged CVEs
}

func (r SeverityLimitRule) Name() string {
	return "SeverityLimitRule"
}

type IgnoredCVE string
type FlaggedCVE string

// Name returns the formatted name of the flagged CVE.
func (r FlaggedCVE) Name() string {
	return fmt.Sprintf("FLAG-%s", string(r))
}

func (r IgnoredCVE) Name() string {
	return fmt.Sprintf("IGNORED-%s", string(r))
}

// ResultCount returns the number of validation results expected for an KubescapeValidatorSpec.
func (s KubescapeValidatorSpec) ResultCount() int {
	count := 0
	if s.SeverityLimitRules != nil {
		count += len(s.SeverityLimitRules)
	}
	return count
}

type SeverityLimits struct {
	Critical   *int `json:"critical,omitempty"`
	High       *int `json:"high,omitempty"`
	Medium     *int `json:"medium,omitempty"`
	Low        *int `json:"low,omitempty"`
	Negligible *int `json:"negligible,omitempty"`
	Unknown    *int `json:"unknown,omitempty"`
}

func (r SeverityLimits) Name() string {
	return "SeverityLimits"
}

// KubescapeValidatorStatus defines the observed state of KubescapeValidator
type KubescapeValidatorStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// KubescapeValidator is the Schema for the kubescapevalidators API
type KubescapeValidator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubescapeValidatorSpec   `json:"spec,omitempty"`
	Status KubescapeValidatorStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KubescapeValidatorList contains a list of KubescapeValidator
type KubescapeValidatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubescapeValidator `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubescapeValidator{}, &KubescapeValidatorList{})
}
