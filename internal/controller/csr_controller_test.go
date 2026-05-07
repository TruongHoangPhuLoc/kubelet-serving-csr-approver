//go:build envtest

// envtest-based integration test for the CSR reconciler.
//
// Run locally:
//
//	go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
//	export KUBEBUILDER_ASSETS=$(setup-envtest use -p path 1.36.0)
//	go test -tags envtest ./internal/controller/...
//
// The test spins up a real kube-apiserver + etcd via envtest, then drives
// the reconciler against it. We test the full code path: PKCS#10 parsing,
// rule evaluation, UpdateApproval PATCH, and the resulting condition on
// the CSR object as the apiserver returns it.

package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"testing"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/TruongHoangPhuLoc/kubelet-serving-csr-approver/internal/controller"
	"github.com/TruongHoangPhuLoc/kubelet-serving-csr-approver/internal/policy"
)

var (
	testEnv     *envtest.Environment
	restCfg     *rest.Config
	adminClient client.Client
)

func TestMain(m *testing.M) {
	testEnv = &envtest.Environment{}
	cfg, err := testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest start: %v\n", err)
		os.Exit(1)
	}
	restCfg = cfg

	adminClient, err = client.New(restCfg, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "build admin client: %v\n", err)
		_ = testEnv.Stop()
		os.Exit(1)
	}

	// envtest doesn't ship the system:node-bootstrapper binding that real
	// clusters carry, so impersonated "system:node:*" identities can't
	// create CSRs by default. Grant cluster-admin to system:nodes so test
	// setup can post CSRs as a node would. This binding is test-only —
	// production RBAC is in deploy/clusterrole.yaml.
	if err := adminClient.Create(context.Background(), &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "test-system-nodes-admin"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{Kind: "Group", Name: "system:nodes", APIGroup: "rbac.authorization.k8s.io"},
		},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "create test RBAC: %v\n", err)
		_ = testEnv.Stop()
		os.Exit(1)
	}

	code := m.Run()
	_ = testEnv.Stop()
	os.Exit(code)
}

// newReconciler builds a reconciler that talks to envtest. Both the
// underlying client.Client and the typed kubernetes.Interface use the
// admin REST config (envtest's default cluster-admin identity).
func newReconciler(t *testing.T) *controller.CSRReconciler {
	t.Helper()
	c, err := client.New(restCfg, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		t.Fatalf("kubernetes.NewForConfig: %v", err)
	}
	return &controller.CSRReconciler{Client: c, Clientset: cs}
}

// nodeClient returns a typed clientset that the apiserver authenticates as
// "system:node:<nodeName>" in group system:nodes — the identity a real
// kubelet would have. Use it to POST a CSR so spec.username/groups carry
// the right node identity instead of the test runner's admin identity.
func nodeClient(t *testing.T, nodeName string) kubernetes.Interface {
	t.Helper()
	icfg := rest.CopyConfig(restCfg)
	icfg.Impersonate = rest.ImpersonationConfig{
		UserName: policy.NodeUserPrefix + nodeName,
		Groups:   []string{policy.NodesGroup, "system:authenticated"},
	}
	cs, err := kubernetes.NewForConfig(icfg)
	if err != nil {
		t.Fatalf("kubernetes.NewForConfig (impersonate): %v", err)
	}
	return cs
}

// makeCSRBytes signs PKCS#10 with a fresh P-256 key. Subject CN/O are
// shaped to satisfy rules 5/6; SANs are the caller's choice.
func makeCSRBytes(t *testing.T, nodeName string, dns []string, ips []net.IP) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   policy.NodeUserPrefix + nodeName,
			Organization: []string{policy.NodesGroup},
		},
		DNSNames:    dns,
		IPAddresses: ips,
	}, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func makeNode(t *testing.T, ctx context.Context, name string, addrs []corev1.NodeAddress) *corev1.Node {
	t.Helper()
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := adminClient.Create(ctx, node); err != nil {
		t.Fatalf("create Node: %v", err)
	}
	t.Cleanup(func() { _ = adminClient.Delete(context.Background(), node) })
	node.Status.Addresses = addrs
	if err := adminClient.Status().Update(ctx, node); err != nil {
		t.Fatalf("update Node status: %v", err)
	}
	return node
}

func makeCSR(t *testing.T, ctx context.Context, name, nodeName string, request []byte) *certv1.CertificateSigningRequest {
	t.Helper()
	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: certv1.CertificateSigningRequestSpec{
			SignerName: policy.KubeletServingSignerName,
			Request:    request,
			Usages: []certv1.KeyUsage{
				certv1.UsageDigitalSignature,
				certv1.UsageKeyEncipherment,
				certv1.UsageServerAuth,
			},
		},
	}
	created, err := nodeClient(t, nodeName).
		CertificatesV1().CertificateSigningRequests().
		Create(ctx, csr, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	t.Cleanup(func() {
		_ = adminClient.Delete(context.Background(), created)
	})
	return created
}

func conditionsTypes(conds []certv1.CertificateSigningRequestCondition) []certv1.RequestConditionType {
	out := make([]certv1.RequestConditionType, 0, len(conds))
	for _, c := range conds {
		out = append(out, c.Type)
	}
	return out
}

// ---- tests ------------------------------------------------------------

func TestReconcile_Approve(t *testing.T) {
	ctx := context.Background()
	rec := newReconciler(t)

	const nodeName = "approve-node"
	makeNode(t, ctx, nodeName, []corev1.NodeAddress{
		{Type: corev1.NodeHostName, Address: nodeName + ".cluster.local"},
		{Type: corev1.NodeInternalIP, Address: "10.0.0.42"},
	})

	csrBytes := makeCSRBytes(t, nodeName,
		[]string{nodeName + ".cluster.local"},
		[]net.IP{net.ParseIP("10.0.0.42")},
	)
	csr := makeCSR(t, ctx, "approve-csr", nodeName, csrBytes)

	if _, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: csr.Name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &certv1.CertificateSigningRequest{}
	if err := adminClient.Get(ctx, types.NamespacedName{Name: csr.Name}, got); err != nil {
		t.Fatalf("get CSR: %v", err)
	}
	if !hasCondition(got.Status.Conditions, certv1.CertificateApproved) {
		t.Errorf("expected Approved, got conditions: %v", conditionsTypes(got.Status.Conditions))
	}
	for _, c := range got.Status.Conditions {
		if c.Type == certv1.CertificateApproved && c.Reason != string(policy.ReasonApproved) {
			t.Errorf("Approved reason = %q, want %q", c.Reason, policy.ReasonApproved)
		}
	}
}

func TestReconcile_DenyNodeNotFound(t *testing.T) {
	ctx := context.Background()
	rec := newReconciler(t)

	// No Node created — rule 8 should fire.
	const nodeName = "ghost-node"
	csrBytes := makeCSRBytes(t, nodeName, nil, nil)
	csr := makeCSR(t, ctx, "deny-csr", nodeName, csrBytes)

	if _, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: csr.Name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &certv1.CertificateSigningRequest{}
	if err := adminClient.Get(ctx, types.NamespacedName{Name: csr.Name}, got); err != nil {
		t.Fatalf("get CSR: %v", err)
	}
	if !hasCondition(got.Status.Conditions, certv1.CertificateDenied) {
		t.Fatalf("expected Denied, got conditions: %v", conditionsTypes(got.Status.Conditions))
	}
	for _, c := range got.Status.Conditions {
		if c.Type == certv1.CertificateDenied && c.Reason != string(policy.ReasonNodeNotFound) {
			t.Errorf("Denied reason = %q, want %q", c.Reason, policy.ReasonNodeNotFound)
		}
	}
}

func TestReconcile_IdempotentOnceDecided(t *testing.T) {
	ctx := context.Background()
	rec := newReconciler(t)

	const nodeName = "idem-node"
	makeNode(t, ctx, nodeName, []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.99"},
	})
	csrBytes := makeCSRBytes(t, nodeName, nil, []net.IP{net.ParseIP("10.0.0.99")})
	csr := makeCSR(t, ctx, "idem-csr", nodeName, csrBytes)

	// First reconcile: decides.
	if _, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: csr.Name}}); err != nil {
		t.Fatalf("Reconcile #1: %v", err)
	}
	first := &certv1.CertificateSigningRequest{}
	if err := adminClient.Get(ctx, types.NamespacedName{Name: csr.Name}, first); err != nil {
		t.Fatalf("get after #1: %v", err)
	}
	if len(first.Status.Conditions) != 1 {
		t.Fatalf("after first reconcile, want 1 condition, got %d: %v",
			len(first.Status.Conditions), first.Status.Conditions)
	}

	// Second reconcile: must not append another condition.
	if _, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: csr.Name}}); err != nil {
		t.Fatalf("Reconcile #2: %v", err)
	}
	second := &certv1.CertificateSigningRequest{}
	if err := adminClient.Get(ctx, types.NamespacedName{Name: csr.Name}, second); err != nil {
		t.Fatalf("get after #2: %v", err)
	}
	if len(second.Status.Conditions) != 1 {
		t.Errorf("idempotency violated: after second reconcile, want 1 condition, got %d: %v",
			len(second.Status.Conditions), second.Status.Conditions)
	}
}

func hasCondition(conds []certv1.CertificateSigningRequestCondition, want certv1.RequestConditionType) bool {
	for _, c := range conds {
		if c.Type == want {
			return true
		}
	}
	return false
}
