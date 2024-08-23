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

// Package controller defines a controller for reconciling KubescapeValidator objects.
package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/go-logr/logr"
	kubevuln "github.com/kubescape/kubevuln/repositories"
	kubescapevalidatorv1 "github.com/validator-labs/validator-plugin-kubescape/api/v1alpha1"
	validationv1 "github.com/validator-labs/validator-plugin-kubescape/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-kubescape/internal/validators"
	"github.com/validator-labs/validator-plugin-kubescape/pkg/constants"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	"github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
	vres "github.com/validator-labs/validator/pkg/validationresult"
)

// KubescapeValidatorReconciler reconciles a KubescapeValidator object
type KubescapeValidatorReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=kubescapevalidators,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=kubescapevalidators/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=kubescapevalidators/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the KubescapeValidator object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile

// Reconcile reconciles each rule found in each KubescapeValidator in the cluster and creates
// ValidationResults accordingly.
func (r *KubescapeValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := r.Log.V(0).WithValues("name", req.Name, "namespace", req.Namespace)
	l.Info("Reconciling Kubescape Validator")

	// Get Kubescape Validation Set
	validator := &validationv1.KubescapeValidator{}
	if err := r.Get(ctx, req.NamespacedName, validator); err != nil {
		if !apierrs.IsNotFound(err) {
			l.Error(err, "failed to fetch KubescapeValidator")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Get the active validator's validation result
	vr := &vapi.ValidationResult{}
	p, err := patch.NewHelper(vr, r.Client)
	if err != nil {
		l.Error(err, "failed to create patch helper")
		return ctrl.Result{}, err
	}
	nn := ktypes.NamespacedName{
		Name:      validationResultName(validator),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		vres.HandleExistingValidationResult(vr, r.Log)
	} else {
		if !apierrs.IsNotFound(err) {
			l.Error(err, "unexpected error getting ValidationResult")
		}
		if err := vres.HandleNewValidationResult(ctx, r.Client, p, buildValidationResult(validator), r.Log); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}

	vr.Spec.ExpectedResults = validator.Spec.ResultCount()

	resp := types.ValidationResponse{
		ValidationRuleResults: make([]*types.ValidationRuleResult, 0, vr.Spec.ExpectedResults),
		ValidationRuleErrors:  make([]error, 0, vr.Spec.ExpectedResults),
	}

	kubescape, err := kubevuln.NewAPIServerStorage(validator.Spec.Namespace)

	if err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 120}, errors.New("cannot connect to kubescape api storage server, is kubescape operator installed?")
	}

	kubescapeService := validators.NewKubescapeService(r.Log, kubescape)

	manifests, err := kubescapeService.Manifests()
	if err != nil {
		return ctrl.Result{RequeueAfter: time.Second * 120}, errors.New("no manifests found")
	}

	// Reconcile Severity Rule
	vrr, err := kubescapeService.ReconcileSeverityRule(validator.Spec.SeverityLimitRule, manifests)
	if err != nil {
		l.Error(err, "failed to reconcile Severity rule")
	}
	resp.AddResult(vrr, err)

	// Reconcile Flagged CVE Rule
	for _, rule := range validator.Spec.FlaggedCVERule {
		fmt.Println("ahash")
		vrr, err := kubescapeService.ReconcileFlaggedCVERule(rule, manifests)
		if err != nil {
			l.Error(err, "failed to reconcile Severity rule")
		}
		resp.AddResult(vrr, err)
	}

	if err := vres.SafeUpdateValidationResult(ctx, p, vr, resp, r.Log); err != nil {
		return ctrl.Result{}, err
	}

	r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
	return ctrl.Result{RequeueAfter: time.Second * 120}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KubescapeValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&validationv1.KubescapeValidator{}).
		Complete(r)
}

func buildValidationResult(validator *kubescapevalidatorv1.KubescapeValidator) *vapi.ValidationResult {
	return &vapi.ValidationResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      validationResultName(validator),
			Namespace: validator.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: validator.APIVersion,
					Kind:       validator.Kind,
					Name:       validator.Name,
					UID:        validator.UID,
					Controller: util.Ptr(true),
				},
			},
		},
		Spec: vapi.ValidationResultSpec{
			Plugin:          constants.PluginCode,
			ExpectedResults: validator.Spec.ResultCount(),
		},
	}
}

func validationResultName(validator *kubescapevalidatorv1.KubescapeValidator) string {
	return fmt.Sprintf("validator-plugin-kubescape-%s", validator.Name)
}
