// Package validators handles Kubescape validation rule reconciliation.
package validators

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	kubevuln "github.com/kubescape/kubevuln/repositories"
	kubescapev1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	validationv1 "github.com/validator-labs/validator-plugin-kubescape/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-kubescape/pkg/constants"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	"github.com/validator-labs/validator/pkg/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type kubescapeRule interface {
	Name() string
}

// KubescapeService retrieves vulnerability data and uses it to reconcile Kubescape rules.
type KubescapeService struct {
	Log logr.Logger
	API *kubevuln.APIServerStore
}

// NewKubescapeService creates a KubescapeService.
func NewKubescapeService(log logr.Logger, kvAPI *kubevuln.APIServerStore) *KubescapeService {
	return &KubescapeService{
		Log: log,
		API: kvAPI,
	}
}

// Manifests retrieves vulnerability data.
func (n *KubescapeService) Manifests() ([]kubescapev1.VulnerabilityManifest, error) {
	manifestList, err := n.API.StorageClient.VulnerabilityManifests("kubescape").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	manifests := make([]kubescapev1.VulnerabilityManifest, 0, len(manifestList.Items))
	for _, v := range manifestList.Items {
		manifest, err := n.API.StorageClient.VulnerabilityManifests("kubescape").Get(context.Background(), v.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		manifests = append(manifests, *manifest)
	}

	return manifests, nil
}

// ReconcileSeverityRule reconciles a severity limit rule.
func (n *KubescapeService) ReconcileSeverityRule(rule validationv1.SeverityLimitRule, manifests []kubescapev1.VulnerabilityManifest) (*types.ValidationRuleResult, error) {
	vr := buildValidationResult(rule, constants.ValidationTypeSeverity)

	critical := 0
	high := 0
	medium := 0
	low := 0
	unknown := 0
	negligible := 0

	foundVulns := validationv1.SeverityLimitRule{
		Critical:   &critical,
		High:       &high,
		Medium:     &medium,
		Low:        &low,
		Unknown:    &unknown,
		Negligible: &negligible,
	}

	uniqueCVEs := make(map[string]bool)

	for _, manifest := range manifests {
		for _, match := range manifest.Spec.Payload.Matches {

			if _, ok := uniqueCVEs[match.Vulnerability.ID]; ok {
				continue
			}

			uniqueCVEs[match.Vulnerability.ID] = true

			switch match.Vulnerability.Severity {
			case "Critical":
				*foundVulns.Critical++
			case "High":
				*foundVulns.High++
			case "Medium":
				*foundVulns.Medium++
			case "Low":
				*foundVulns.Low++
			case "Unknown":
				*foundVulns.Unknown++
			case "Negligible":
				*foundVulns.Negligible++
			}
		}
	}

	var diff int
	if rule.Critical != nil && *foundVulns.Critical > *rule.Critical {
		vr.Condition.Status = v1.ConditionFalse
		diff = *foundVulns.Critical - *rule.Critical
		vr.Condition.Details = append(vr.Condition.Details, fmt.Sprintf("Found %d unique Critical severity vulnerabilities. %d higher then %d limit.", *foundVulns.Critical, diff, *rule.Critical))
	}

	if rule.High != nil && *foundVulns.High > *rule.High {
		vr.Condition.Status = v1.ConditionFalse
		diff = *foundVulns.High - *rule.High
		vr.Condition.Details = append(vr.Condition.Details, fmt.Sprintf("Found %d High severity vulnerabilities. %d higher then %d limit.", *foundVulns.High, diff, *rule.High))
	}

	if rule.Medium != nil && *foundVulns.Medium > *rule.Medium {
		vr.Condition.Status = v1.ConditionFalse
		diff = *foundVulns.Medium - *rule.Medium
		vr.Condition.Details = append(vr.Condition.Details, fmt.Sprintf("Found %d Medium severity vulnerabilities. %d higher then %d limit.", *foundVulns.Medium, diff, *rule.Medium))

	}

	if rule.Low != nil && *foundVulns.Low > *rule.Low {
		vr.Condition.Status = v1.ConditionFalse
		diff = *foundVulns.Low - *rule.Low
		vr.Condition.Details = append(vr.Condition.Details, fmt.Sprintf("Found %d Low severity vulnerabilities. %d higher then %d limit.", *foundVulns.Low, diff, *rule.Low))

	}

	if rule.Unknown != nil && *foundVulns.Unknown > *rule.Unknown {
		vr.Condition.Status = v1.ConditionFalse
		diff = *foundVulns.Unknown - *rule.Unknown
		vr.Condition.Details = append(vr.Condition.Details, fmt.Sprintf("Found %d Unknown severity vulnerabilities. %d higher then %d limit.", *foundVulns.Unknown, diff, *rule.Unknown))

	}

	if rule.Negligible != nil && *foundVulns.Negligible > *rule.Negligible {
		vr.Condition.Status = v1.ConditionFalse
		diff = *foundVulns.Negligible - *rule.Negligible
		vr.Condition.Details = append(vr.Condition.Details, fmt.Sprintf("Found %d Negligible severity vulnerabilities. %d higher then %d limit.", *foundVulns.Negligible, diff, *rule.Negligible))
	}

	if vr.Condition.Status == v1.ConditionFalse {
		vr.Condition.Message = "Some kubescape-severity limit checks failed."
	}

	return vr, nil
}

// ReconcileFlaggedCVERule reconciles a flagged CVE rule.
func (n *KubescapeService) ReconcileFlaggedCVERule(cve validationv1.FlaggedCVE, manifests []kubescapev1.VulnerabilityManifest) (*types.ValidationRuleResult, error) {
	vr := buildValidationResult(cve, constants.ValidationTypeSeverity)

	count := 0

	checkedImages := make(map[string]bool)

	for _, manifest := range manifests {
		for _, match := range manifest.Spec.Payload.Matches {
			if match.Vulnerability.ID == string(cve) {
				vr.Condition.Status = v1.ConditionFalse
				imageTag := manifest.Annotations["kubescape.io/image-tag"]

				if _, ok := checkedImages[imageTag]; ok {
					continue
				}

				checkedImages[imageTag] = true
				count++

				vr.Condition.Details = append(vr.Condition.Details, fmt.Sprintf("%s found in %s", match.Vulnerability.ID, imageTag))
				vr.Condition.Failures = append(vr.Condition.Failures, imageTag)
			}
		}
	}
	vr.Condition.Message = fmt.Sprintf("Vulnerability found within cluster. %s found in cluster %d times.", string(cve), count)

	return vr, nil

}

func buildValidationResult(rule kubescapeRule, validationType string) *types.ValidationRuleResult {
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Details = make([]string, 0)
	latestCondition.Failures = make([]string, 0)
	latestCondition.Message = fmt.Sprintf("All %s checks passed", validationType)
	latestCondition.ValidationRule = rule.Name()
	latestCondition.ValidationType = validationType
	return &types.ValidationRuleResult{Condition: &latestCondition, State: &state}
}
