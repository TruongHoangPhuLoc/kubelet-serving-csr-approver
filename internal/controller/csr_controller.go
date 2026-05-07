// Package controller wires the CertificateSigningRequest informer to the
// policy evaluator and applies the decision via the /approval subresource.
// It owns ONLY the approval gate; kube-controller-manager continues to do
// the actual signing.
package controller

import (
	"context"
	"fmt"
	"strings"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/TruongHoangPhuLoc/kubelet-serving-csr-approver/internal/policy"
)

const controllerName = "kubelet-csr-approver"

// CSRReconciler evaluates pending kubelet-serving CSRs and applies the
// decision via the /approval subresource. The cached client.Client is used
// for reads; the typed clientset is used for the approval PATCH because
// generic SubResource("approval") is not as battle-tested as the generated
// CertificatesV1().UpdateApproval call for this specific subresource.
type CSRReconciler struct {
	client.Client
	Clientset kubernetes.Interface
}

func (r *CSRReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx).WithValues("csr", req.Name)

	var csr certv1.CertificateSigningRequest
	if err := r.Get(ctx, req.NamespacedName, &csr); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	// The predicate already filters these, but a CSR can transition between
	// list/watch and Reconcile — re-check defensively.
	if csr.Spec.SignerName != policy.KubeletServingSignerName {
		return reconcile.Result{}, nil
	}
	if len(csr.Status.Conditions) > 0 {
		return reconcile.Result{}, nil
	}

	// Best-effort node fetch. If username doesn't match the node-user prefix,
	// policy rule 2 will deny — we still call Evaluate so the rejection is
	// applied uniformly with a reason.
	var node *corev1.Node
	if name, ok := nodeNameFromUsername(csr.Spec.Username); ok {
		var n corev1.Node
		switch err := r.Get(ctx, types.NamespacedName{Name: name}, &n); {
		case err == nil:
			node = &n
		case apierrors.IsNotFound(err):
			// Leave node = nil; policy rule 8 denies on this.
		default:
			return reconcile.Result{}, err
		}
	}

	decision, reason := policy.Evaluate(&csr, node)

	if err := r.applyDecision(ctx, &csr, decision, reason); err != nil {
		// On 409 (someone else decided first) or transient API error, return
		// to controller-runtime — it will requeue and our predicate will
		// filter the now-decided CSR back out.
		logger.Error(err, "applying decision failed",
			"username", csr.Spec.Username,
			"decision", decision,
			"reason", reason,
		)
		return reconcile.Result{}, err
	}

	logger.Info("csr decision applied",
		"username", csr.Spec.Username,
		"decision", decision,
		"reason", reason,
	)
	return reconcile.Result{}, nil
}

// applyDecision attaches the Approved / Denied condition to a copy of csr
// and PATCHes the /approval subresource. KCM consumes the result and
// either signs the cert (Approved) or marks the CSR Failed (Denied).
func (r *CSRReconciler) applyDecision(
	ctx context.Context,
	csr *certv1.CertificateSigningRequest,
	decision policy.Decision,
	reason policy.Reason,
) error {
	// Never mutate the cache-shared object.
	toUpdate := csr.DeepCopy()

	cond := certv1.CertificateSigningRequestCondition{
		Status:         corev1.ConditionTrue,
		Reason:         string(reason),
		LastUpdateTime: metav1.Now(),
	}
	switch decision {
	case policy.Approve:
		cond.Type = certv1.CertificateApproved
		cond.Message = fmt.Sprintf("auto-approved by kubelet-csr-approver (%s)", reason)
	case policy.Deny:
		cond.Type = certv1.CertificateDenied
		cond.Message = fmt.Sprintf("auto-denied by kubelet-csr-approver (%s)", reason)
	default:
		return fmt.Errorf("unknown policy decision %q", decision)
	}
	toUpdate.Status.Conditions = append(toUpdate.Status.Conditions, cond)

	_, err := r.Clientset.
		CertificatesV1().
		CertificateSigningRequests().
		UpdateApproval(ctx, toUpdate.Name, toUpdate, metav1.UpdateOptions{})
	return err
}

// SetupWithManager registers the controller and its predicate with mgr.
// The kubernetes typed clientset is built from mgr's REST config — only the
// reconciler needs it, so we keep this dependency internal to the package.
func SetupWithManager(mgr ctrl.Manager) error {
	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("build kubernetes clientset: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named(controllerName).
		For(&certv1.CertificateSigningRequest{}, builder.WithPredicates(kubeletServingPredicate())).
		Complete(&CSRReconciler{Client: mgr.GetClient(), Clientset: clientset})
}

// kubeletServingPredicate keeps the queue tight: only kubelet-serving CSRs that
// have not yet been decided. Decided CSRs (Approved or Denied conditions set)
// and CSRs for other signers never enter the workqueue.
func kubeletServingPredicate() predicate.Predicate {
	matches := func(obj client.Object) bool {
		csr, ok := obj.(*certv1.CertificateSigningRequest)
		if !ok {
			return false
		}
		if csr.Spec.SignerName != policy.KubeletServingSignerName {
			return false
		}
		return len(csr.Status.Conditions) == 0
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return matches(e.Object) },
		UpdateFunc:  func(e event.UpdateEvent) bool { return matches(e.ObjectNew) },
		DeleteFunc:  func(event.DeleteEvent) bool { return false },
		GenericFunc: func(e event.GenericEvent) bool { return matches(e.Object) },
	}
}

func nodeNameFromUsername(u string) (string, bool) {
	if !strings.HasPrefix(u, policy.NodeUserPrefix) {
		return "", false
	}
	name := strings.TrimPrefix(u, policy.NodeUserPrefix)
	if name == "" {
		return "", false
	}
	return name, true
}
