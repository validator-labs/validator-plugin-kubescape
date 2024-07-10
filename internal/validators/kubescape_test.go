package validators

import (
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	kubevuln "github.com/kubescape/kubevuln/repositories"
	kubescapev1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	validationv1 "github.com/validator-labs/validator-plugin-kubescape/api/v1alpha1"
	"github.com/validator-labs/validator/pkg/types"
)

func TestKubescapeService_ReconcileSeverityRule(t *testing.T) {
	type fields struct {
		Log logr.Logger
		API *kubevuln.APIServerStore
	}
	type args struct {
		rule      validationv1.SeverityLimitRule
		manifests []kubescapev1.VulnerabilityManifest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *types.ValidationRuleResult
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &KubescapeService{
				Log: tt.fields.Log,
				API: tt.fields.API,
			}
			got, err := n.ReconcileSeverityRule(tt.args.rule, tt.args.manifests)
			if (err != nil) != tt.wantErr {
				t.Errorf("KubescapeService.ReconcileSeverityRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KubescapeService.ReconcileSeverityRule() = %v, want %v", got, tt.want)
			}
		})
	}
}
