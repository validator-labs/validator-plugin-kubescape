package validators

import (
	"context"
	"fmt"
	"slices"

	"github.com/go-logr/logr"
	kubevuln "github.com/kubescape/kubevuln/repositories"
	kubescapev1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	validationv1 "github.com/spectrocloud-labs/validator-plugin-kubescape/api/v1"
	"github.com/spectrocloud-labs/validator-plugin-kubescape/internal/constants"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	"github.com/spectrocloud-labs/validator/pkg/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
)

type kubescapeRule interface {
	Name() string
}

type KubescapeService struct {
	Log              logr.Logger
	kvApiServerStore *kubevuln.APIServerStore
}

func NewKubescapeService(log logr.Logger, kvApi *kubevuln.APIServerStore) *KubescapeService {
	return &KubescapeService{
		Log:              log,
		kvApiServerStore: kvApi,
	}
}

func (n *KubescapeService) ReconcileSeverityRule(nn ktypes.NamespacedName, rule validationv1.SeverityLimitRule, ignoredVulnerabilities []string) (*types.ValidationRuleResult, error) {
	vr := buildValidationResult(rule, constants.ValidationTypeSeverity)

	manifestList, err := n.kvApiServerStore.StorageClient.VulnerabilityManifests("kubescape").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return vr, err
	}

	var manifests []kubescapev1.VulnerabilityManifest

	checked := make(map[string]bool)
	summary := make(map[string]int)
	matches := []kubescapev1.Match{}

	for _, v := range manifestList.Items {
		manifest, err := n.kvApiServerStore.StorageClient.VulnerabilityManifests("kubescape").Get(context.Background(), v.Name, metav1.GetOptions{})
		if err != nil {
			return vr, err
		}

		manifests = append(manifests, *manifest)

		for _, match := range manifest.Spec.Payload.Matches {
			// make sure it is a unique CVE
			if val, ok := checked[match.Vulnerability.ID]; ok && val {
				continue
			}

			if ok := slices.Contains(ignoredVulnerabilities, match.Vulnerability.ID); ok {
				continue
			}

			checked[match.Vulnerability.ID] = true
			matches = append(matches, match)

			// TODO: better details
			vr.Condition.Details = append(vr.Condition.Details, match.Vulnerability.ID)

			if _, ok := summary[match.Vulnerability.Severity]; ok {
				summary[match.Vulnerability.Severity] += 1
			} else {
				summary[match.Vulnerability.Severity] = 0
			}

		}
	}

	// Checking Vulnerability Counts
	if summary["Critical"] > rule.Critical {
		vr.Condition.Status = v1.ConditionFalse
	}

	if summary["High"] > rule.High {
		vr.Condition.Status = v1.ConditionFalse
	}

	if summary["Medium"] > rule.Medium {
		vr.Condition.Status = v1.ConditionFalse
	}

	if summary["Low"] > rule.Low {
		vr.Condition.Status = v1.ConditionFalse
	}

	if summary["Unknown"] > rule.Unknown {
		vr.Condition.Status = v1.ConditionFalse
	}

	if summary["Negligible"] > rule.Negligible {
		vr.Condition.Status = v1.ConditionFalse
	}

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
