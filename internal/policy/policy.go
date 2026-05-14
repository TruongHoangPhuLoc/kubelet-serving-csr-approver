// Package policy contains the pure decision function for kubelet-serving CSRs.
//
// Evaluate is intentionally a pure function of (CSR, Node) so it can be
// table-tested exhaustively in isolation from the controller, the API server,
// and the network. It performs no client calls, no DNS, and no logging.
package policy

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
)

// oidSubjectAltName is RFC 5280's SubjectAltName extension. It is the only
// PKCS#10 extension this controller accepts — its content is vetted by
// rules 9 (DNS), 10 (IP), and 11 (forbidden Email/URI). Everything else
// (BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectKeyIdentifier,
// custom OIDs, …) is the signer's prerogative or the kubelet overstepping;
// either way we don't approve CSRs that ask for them.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// Decision is the verdict returned by Evaluate.
type Decision string

const (
	Approve Decision = "Approve"
	Deny    Decision = "Deny"
)

// Reason names the rule that drove the Decision. On Approve, ReasonApproved is
// returned. On Deny, the constant is the first failing rule (rules are checked
// in numeric order, fail-closed).
type Reason string

const (
	ReasonApproved Reason = "Approved"

	ReasonSignerMismatch      Reason = "SignerMismatch"      // rule 1
	ReasonUsernameInvalid     Reason = "UsernameInvalid"     // rule 2
	ReasonNotInNodeGroup      Reason = "NotInNodeGroup"      // rule 3
	ReasonCSRParseError       Reason = "CSRParseError"       // rule 4
	ReasonCommonNameMismatch  Reason = "CommonNameMismatch"  // rule 5
	ReasonOrganizationInvalid Reason = "OrganizationInvalid" // rule 6
	ReasonUsagesInvalid       Reason = "UsagesInvalid"       // rule 7
	ReasonNodeNotFound        Reason = "NodeNotFound"        // rule 8
	ReasonDNSSANUnauthorized  Reason = "DNSSANUnauthorized"  // rule 9
	ReasonIPSANUnauthorized   Reason = "IPSANUnauthorized"   // rule 10
	ReasonForbiddenSANType    Reason = "ForbiddenSANType"    // rule 11
	ReasonUnknownExtension    Reason = "UnknownExtension"    // rule 12
)

const (
	// KubeletServingSignerName is the only signer this controller acts on.
	KubeletServingSignerName = "kubernetes.io/kubelet-serving"

	// NodeUserPrefix prefixes the apiserver-set username for node identities.
	NodeUserPrefix = "system:node:"

	// NodesGroup must appear in spec.groups for a node CSR.
	NodesGroup = "system:nodes"
)

// Evaluate applies rules 1–12 in order and returns at the first failure.
// node may be nil; rules that need it (8–10) treat nil as "node not found".
func Evaluate(csr *certv1.CertificateSigningRequest, node *corev1.Node) (Decision, Reason) {
	// Rule 1: signerName.
	if csr.Spec.SignerName != KubeletServingSignerName {
		return Deny, ReasonSignerMismatch
	}

	// Rule 2: spec.username == system:node:<nodeName>. The apiserver fills this
	// from the authenticated identity; it is the root of trust.
	nodeName, ok := nodeNameFromUsername(csr.Spec.Username)
	if !ok {
		return Deny, ReasonUsernameInvalid
	}

	// Rule 3: spec.groups contains system:nodes.
	if !slices.Contains(csr.Spec.Groups, NodesGroup) {
		return Deny, ReasonNotInNodeGroup
	}

	// Rule 4: parse spec.request as PKCS#10 and verify the embedded
	// self-signature. The parsed result feeds rules 5, 6, 9–12.
	cr, err := parseAndVerifyCSR(csr.Spec.Request)
	if err != nil {
		return Deny, ReasonCSRParseError
	}

	// Rule 5: parsed CommonName must equal "system:node:<nodeName>", using
	// the *trusted* nodeName from rule 2. This is the cross-check that stops
	// a kubelet authenticated as node A from getting a cert whose subject
	// claims it is node B.
	if cr.Subject.CommonName != NodeUserPrefix+nodeName {
		return Deny, ReasonCommonNameMismatch
	}

	// Rule 6: parsed Subject.Organization must be exactly [NodesGroup].
	// Strict equality — extra entries are forbidden, since RBAC bindings on
	// "system:nodes" are the basis of node authorization. Adding an extra
	// O to a node cert would not grant new privileges (groups come from
	// authentication, not the cert) but it would still be a deviation
	// from the kubelet contract worth refusing fail-closed.
	if !slices.Equal(cr.Subject.Organization, []string{NodesGroup}) {
		return Deny, ReasonOrganizationInvalid
	}

	// Rule 7: usages must include {server auth, digital signature} and may
	// additionally include {key encipherment}. No other entries are allowed.
	// In particular, "client auth" is forbidden — this is a serving cert,
	// not a client cert.
	//
	// The original spec called for "exactly {digital signature, key
	// encipherment, server auth}", but real kubelets using ECDSA keys
	// (P-256 by default since at least Kubernetes 1.19) deliberately
	// OMIT key encipherment — that usage is only meaningful for RSA key
	// transport and ECDSA TLS server auth never needs it. We accept both
	// shapes; the security-critical invariant (no client auth, no surprise
	// EKUs) is unchanged.
	if !usagesValidForServerAuth(csr.Spec.Usages) {
		return Deny, ReasonUsagesInvalid
	}

	// Rule 8: Node object exists. The caller fetches the Node by the trusted
	// nodeName from rule 2; nil here means the API returned NotFound. This
	// rule is the prerequisite for rules 9–10: their security claim ("every
	// SAN must appear in node.status.addresses") is meaningless without a
	// Node, so an absent Node must fail closed.
	if node == nil {
		return Deny, ReasonNodeNotFound
	}

	// Rule 9: every DNS SAN in the CSR must appear in node.Status.Addresses
	// with type Hostname / InternalDNS / ExternalDNS. We never resolve DNS —
	// the Node is the only source of truth, because DNS is mutable from
	// outside the cluster.
	if !dnsSANsCovered(cr.DNSNames, node.Status.Addresses) {
		return Deny, ReasonDNSSANUnauthorized
	}

	// Rule 10: every IP SAN must appear with type InternalIP / ExternalIP.
	if !ipSANsCovered(cr.IPAddresses, node.Status.Addresses) {
		return Deny, ReasonIPSANUnauthorized
	}

	// Rule 11: no Email or URI SANs. Kubelet serving certs identify a node
	// via DNS / IP only. Email and URI SANs have no role in TLS server-name
	// matching but could be misused for unrelated identity (e.g. SPIFFE) —
	// fail closed.
	if len(cr.EmailAddresses) > 0 || len(cr.URIs) > 0 {
		return Deny, ReasonForbiddenSANType
	}

	// Rule 12: every extension in the PKCS#10 must be on our allowlist.
	// cr.ExtraExtensions is a creation-time field — Go's parser leaves it
	// empty and routes everything into cr.Extensions, so we only iterate
	// the latter.
	for _, ext := range cr.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			return Deny, ReasonUnknownExtension
		}
	}

	return Approve, ReasonApproved
}

// parseAndVerifyCSR PEM-decodes req, parses the DER as a PKCS#10
// CertificateRequest, and verifies the embedded self-signature.
//
// "Self-signature" here means the signature was produced by the private key
// matching the public key carried in the CSR — this is what
// crypto/x509.CertificateRequest.CheckSignature verifies. It does NOT vouch
// for the requester's identity (that's handled by spec.username, rule 2);
// it only proves the requester controls the key they're asking us to sign.
func parseAndVerifyCSR(req []byte) (*x509.CertificateRequest, error) {
	if len(req) == 0 {
		return nil, errors.New("spec.request is empty")
	}
	block, _ := pem.Decode(req)
	if block == nil {
		return nil, errors.New("spec.request is not PEM-encoded")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
	cr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#10: %w", err)
	}
	if err := cr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify CSR self-signature: %w", err)
	}
	return cr, nil
}

// nodeNameFromUsername extracts the kubelet's node name from spec.username.
// Returns ok=false if the prefix is missing or the suffix is empty.
func nodeNameFromUsername(u string) (string, bool) {
	if !strings.HasPrefix(u, NodeUserPrefix) {
		return "", false
	}
	name := strings.TrimPrefix(u, NodeUserPrefix)
	if name == "" {
		return "", false
	}
	return name, true
}

// dnsSANsCovered checks that every DNS name in want appears, after
// canonicalisation, in the Hostname / InternalDNS / ExternalDNS entries
// of addrs. An empty want is vacuously covered.
func dnsSANsCovered(want []string, addrs []corev1.NodeAddress) bool {
	have := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		switch a.Type {
		case corev1.NodeHostName, corev1.NodeInternalDNS, corev1.NodeExternalDNS:
			if a.Address == "" {
				continue
			}
			have[canonDNS(a.Address)] = struct{}{}
		}
	}
	for _, name := range want {
		if _, ok := have[canonDNS(name)]; !ok {
			return false
		}
	}
	return true
}

// ipSANsCovered checks that every IP in want appears in the InternalIP /
// ExternalIP entries of addrs. Comparison is value-based via net.IP.Equal,
// which handles 4-byte vs 16-byte IPv4 representations transparently.
func ipSANsCovered(want []net.IP, addrs []corev1.NodeAddress) bool {
	var have []net.IP
	for _, a := range addrs {
		switch a.Type {
		case corev1.NodeInternalIP, corev1.NodeExternalIP:
			if ip := net.ParseIP(a.Address); ip != nil {
				have = append(have, ip)
			}
		}
	}
	for _, w := range want {
		match := false
		for _, h := range have {
			if h.Equal(w) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// canonDNS lowercases and strips a single trailing dot. DNS labels are
// case-insensitive (RFC 4343); the trailing dot just distinguishes the
// FQDN form (RFC 1034) and shouldn't gate equality.
func canonDNS(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// usagesValidForServerAuth returns true iff have:
//   - contains both ServerAuth and DigitalSignature (required for TLS server auth)
//   - contains no entries outside {ServerAuth, DigitalSignature, KeyEncipherment}
//   - contains no duplicates
//
// KeyEncipherment is allowed but not required: it's only meaningful for RSA
// key transport, and modern kubelets using ECDSA P-256 keys omit it. The
// security-critical clause is the closed allowlist — ClientAuth and any
// other surprise EKU are rejected by the second bullet.
func usagesValidForServerAuth(have []certv1.KeyUsage) bool {
	allowed := map[certv1.KeyUsage]bool{
		certv1.UsageServerAuth:       true,
		certv1.UsageDigitalSignature: true,
		certv1.UsageKeyEncipherment:  true,
	}
	seen := make(map[certv1.KeyUsage]bool, len(have))
	for _, u := range have {
		if !allowed[u] || seen[u] {
			return false
		}
		seen[u] = true
	}
	return seen[certv1.UsageServerAuth] && seen[certv1.UsageDigitalSignature]
}
