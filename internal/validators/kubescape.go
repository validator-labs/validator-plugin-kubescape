package validators

import (
	"context"
	"fmt"

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
	log              logr.Logger
	kvApiServerStore *kubevuln.APIServerStore
}

func NewKubescapeService(log logr.Logger, kvApi *kubevuln.APIServerStore) *KubescapeService {
	return &KubescapeService{
		log:              log,
		kvApiServerStore: kvApi,
	}
}

func (n *KubescapeService) ReconcileSeverityRule(nn ktypes.NamespacedName, rule validationv1.SeverityLimitRule) (*types.ValidationRuleResult, error) {
	vr := buildValidationResult(rule, constants.ValidationTypeSeverity)

	manifests, err := n.kvApiServerStore.StorageClient.VulnerabilityManifestSummaries("kubescape").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return vr, err
	}

	var vuln []kubescapev1.VulnerabilityManifestSummary
	vulnerabilityCount := validationv1.SeverityLimitRule{}

	for _, v := range manifests.Items {

		m, err := n.kvApiServerStore.StorageClient.VulnerabilityManifestSummaries("kubescape").Get(context.Background(), v.Name, metav1.GetOptions{})

		if err != nil {
			return vr, err
		}

		vuln = append(vuln, *m)

		vulnerabilityCount.Critical += m.Spec.Severities.Critical.All
		vulnerabilityCount.High += m.Spec.Severities.High.All
		vulnerabilityCount.Medium += m.Spec.Severities.Medium.All
		vulnerabilityCount.Low += m.Spec.Severities.Low.All
		vulnerabilityCount.Negligible += m.Spec.Severities.Negligible.All
		vulnerabilityCount.Unknown += m.Spec.Severities.Unknown.All
	}

	if vulnerabilityCount.Critical > rule.Critical {
		vr.Condition.Status = v1.ConditionFalse
	}

	if vulnerabilityCount.High > rule.High {
		vr.Condition.Status = v1.ConditionFalse
	}

	if vulnerabilityCount.Medium > rule.Medium {
		vr.Condition.Status = v1.ConditionFalse
	}

	if vulnerabilityCount.Low > rule.Low {
		vr.Condition.Status = v1.ConditionFalse
	}

	if vulnerabilityCount.Unknown > rule.Unknown {
		vr.Condition.Status = v1.ConditionFalse
	}

	if vulnerabilityCount.Negligible > rule.Negligible {
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
