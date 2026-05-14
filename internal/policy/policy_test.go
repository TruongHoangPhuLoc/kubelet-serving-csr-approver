package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/url"
	"testing"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
)

// mustCSRBytesFull signs the given template with a fresh P-256 key and
// returns PEM-encoded PKCS#10 bytes. Tests use this to construct CSRs that
// violate a specific rule, including SAN-related rules.
func mustCSRBytesFull(t *testing.T, template *x509.CertificateRequest) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// mustCSRBytes is the subject-only convenience over mustCSRBytesFull.
func mustCSRBytes(t *testing.T, subject pkix.Name) []byte {
	return mustCSRBytesFull(t, &x509.CertificateRequest{Subject: subject})
}

// mustValidCSRBytes returns PEM-encoded PKCS#10 bytes whose Subject is
// shaped to satisfy rules 5 and 6.
func mustValidCSRBytes(t *testing.T, nodeName string) []byte {
	t.Helper()
	return mustCSRBytes(t, pkix.Name{
		CommonName:   NodeUserPrefix + nodeName,
		Organization: []string{NodesGroup},
	})
}

// validBaselineSubject returns the Subject every non-rule-5/6 case uses.
func validBaselineSubject(nodeName string) pkix.Name {
	return pkix.Name{
		CommonName:   NodeUserPrefix + nodeName,
		Organization: []string{NodesGroup},
	}
}

func validBaselineNode() *corev1.Node {
	return &corev1.Node{}
}

func TestEvaluate(t *testing.T) {
	// Generate one valid PKCS#10 blob and reuse it across cases that don't
	// specifically tamper with the request — rule 1/2/3 negatives reject
	// before rule 4 anyway, but giving them valid bytes keeps each test
	// independent of evaluation order.
	const nodeName = "worker-1"
	validRequest := mustValidCSRBytes(t, nodeName)

	baselineCSR := func() *certv1.CertificateSigningRequest {
		return &certv1.CertificateSigningRequest{
			Spec: certv1.CertificateSigningRequestSpec{
				SignerName: KubeletServingSignerName,
				Username:   "system:node:" + nodeName,
				Groups:     []string{"system:authenticated", NodesGroup},
				Usages: []certv1.KeyUsage{
					certv1.UsageDigitalSignature,
					certv1.UsageKeyEncipherment,
					certv1.UsageServerAuth,
				},
				Request: validRequest,
			},
		}
	}

	type tc struct {
		name       string
		mutate     func(*certv1.CertificateSigningRequest)
		node       *corev1.Node // nil + !nilNode → use validBaselineNode
		nilNode    bool         // pass nil to Evaluate (for rule 8 negatives)
		want       Decision
		wantReason Reason
		skip       string // non-empty → t.Skip
	}

	cases := []tc{
		{
			name:       "baseline: all valid → approve",
			mutate:     func(*certv1.CertificateSigningRequest) {},
			want:       Approve,
			wantReason: ReasonApproved,
		},
		// ---- rule 1 ---------------------------------------------------------
		{
			name: "rule 1: signer mismatch",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.SignerName = "kubernetes.io/kube-apiserver-client-kubelet"
			},
			want:       Deny,
			wantReason: ReasonSignerMismatch,
		},
		// ---- rule 2 ---------------------------------------------------------
		{
			name: "rule 2: username missing system:node: prefix",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Username = "kubelet-bootstrap"
			},
			want:       Deny,
			wantReason: ReasonUsernameInvalid,
		},
		{
			name: "rule 2: empty node name after prefix",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Username = "system:node:"
			},
			want:       Deny,
			wantReason: ReasonUsernameInvalid,
		},
		// ---- rule 3 ---------------------------------------------------------
		{
			name: "rule 3: missing system:nodes group",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Groups = []string{"system:authenticated"}
			},
			want:       Deny,
			wantReason: ReasonNotInNodeGroup,
		},
		// ---- rule 4 ---------------------------------------------------------
		{
			name: "rule 4: empty request",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = nil
			},
			want:       Deny,
			wantReason: ReasonCSRParseError,
		},
		{
			name: "rule 4: not PEM",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = []byte("this is not pem-encoded")
			},
			want:       Deny,
			wantReason: ReasonCSRParseError,
		},
		{
			name: "rule 4: PEM block type wrong",
			mutate: func(c *certv1.CertificateSigningRequest) {
				block, _ := pem.Decode(c.Spec.Request)
				block.Type = "CERTIFICATE"
				c.Spec.Request = pem.EncodeToMemory(block)
			},
			want:       Deny,
			wantReason: ReasonCSRParseError,
		},
		{
			name: "rule 4: garbage DER inside valid PEM frame",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: []byte("not valid asn.1 der"),
				})
			},
			want:       Deny,
			wantReason: ReasonCSRParseError,
		},
		{
			name: "rule 4: tampered self-signature",
			mutate: func(c *certv1.CertificateSigningRequest) {
				// Flip the last DER byte. For ECDSA-P256 this lands inside
				// the s integer of the signature SEQUENCE — ASN.1 length
				// framing is preserved, parse succeeds, signature
				// verification fails.
				block, _ := pem.Decode(c.Spec.Request)
				block.Bytes[len(block.Bytes)-1] ^= 0xFF
				c.Spec.Request = pem.EncodeToMemory(block)
			},
			want:       Deny,
			wantReason: ReasonCSRParseError,
		},
		// ---- rule 5 ---------------------------------------------------------
		{
			name: "rule 5: CN names a different node",
			mutate: func(c *certv1.CertificateSigningRequest) {
				// Username (rule 2) trusts "worker-1"; this CSR's CN claims "imposter".
				c.Spec.Request = mustCSRBytes(t, pkix.Name{
					CommonName:   NodeUserPrefix + "imposter",
					Organization: []string{NodesGroup},
				})
			},
			want:       Deny,
			wantReason: ReasonCommonNameMismatch,
		},
		{
			name: "rule 5: CN missing system:node: prefix",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytes(t, pkix.Name{
					CommonName:   nodeName, // raw, no prefix
					Organization: []string{NodesGroup},
				})
			},
			want:       Deny,
			wantReason: ReasonCommonNameMismatch,
		},
		{
			name: "rule 5: CN empty",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytes(t, pkix.Name{
					Organization: []string{NodesGroup},
				})
			},
			want:       Deny,
			wantReason: ReasonCommonNameMismatch,
		},
		// ---- rule 6 ---------------------------------------------------------
		{
			name: "rule 6: Organization missing",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytes(t, pkix.Name{
					CommonName: NodeUserPrefix + nodeName,
				})
			},
			want:       Deny,
			wantReason: ReasonOrganizationInvalid,
		},
		{
			name: "rule 6: Organization wrong group",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytes(t, pkix.Name{
					CommonName:   NodeUserPrefix + nodeName,
					Organization: []string{"system:masters"},
				})
			},
			want:       Deny,
			wantReason: ReasonOrganizationInvalid,
		},
		{
			name: "rule 6: Organization has system:nodes plus extras",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytes(t, pkix.Name{
					CommonName:   NodeUserPrefix + nodeName,
					Organization: []string{NodesGroup, "extra-team"},
				})
			},
			want:       Deny,
			wantReason: ReasonOrganizationInvalid,
		},
		{
			name: "rule 6: Organization duplicated system:nodes",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytes(t, pkix.Name{
					CommonName:   NodeUserPrefix + nodeName,
					Organization: []string{NodesGroup, NodesGroup},
				})
			},
			want:       Deny,
			wantReason: ReasonOrganizationInvalid,
		},
		// ---- rule 7 ---------------------------------------------------------
		{
			// Real kubelets using ECDSA keys (P-256, default for years) submit
			// CSRs with exactly these two usages — key encipherment is omitted
			// because it's only meaningful for RSA key transport. Locked in
			// after finding this on a real cluster: every CSR from k8s-worker-
			// node-02 was being denied UsagesInvalid by the original
			// "exactly three" check.
			name: "rule 7: ECDSA-style usages (no key encipherment) approve",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Usages = []certv1.KeyUsage{
					certv1.UsageDigitalSignature,
					certv1.UsageServerAuth,
				}
			},
			want:       Approve,
			wantReason: ReasonApproved,
		},
		{
			name: "rule 7: missing server auth",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Usages = []certv1.KeyUsage{
					certv1.UsageDigitalSignature,
					certv1.UsageKeyEncipherment,
				}
			},
			want:       Deny,
			wantReason: ReasonUsagesInvalid,
		},
		{
			name: "rule 7: client auth forbidden",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Usages = []certv1.KeyUsage{
					certv1.UsageDigitalSignature,
					certv1.UsageKeyEncipherment,
					certv1.UsageServerAuth,
					certv1.UsageClientAuth,
				}
			},
			want:       Deny,
			wantReason: ReasonUsagesInvalid,
		},
		{
			name: "rule 7: duplicate usage rejected",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Usages = []certv1.KeyUsage{
					certv1.UsageDigitalSignature,
					certv1.UsageDigitalSignature,
					certv1.UsageServerAuth,
				}
			},
			want:       Deny,
			wantReason: ReasonUsagesInvalid,
		},
		// ---- rule 8 ---------------------------------------------------------
		{
			name:       "rule 8: Node object missing",
			mutate:     func(*certv1.CertificateSigningRequest) {},
			nilNode:    true,
			want:       Deny,
			wantReason: ReasonNodeNotFound,
		},
		// ---- rule 9 ---------------------------------------------------------
		{
			name: "rule 9: DNS SAN matches Hostname",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:  validBaselineSubject(nodeName),
					DNSNames: []string{"worker-1.cluster.local"},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeHostName, Address: "worker-1.cluster.local"},
			}}},
			want:       Approve,
			wantReason: ReasonApproved,
		},
		{
			name: "rule 9: DNS SAN matches InternalDNS / ExternalDNS",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:  validBaselineSubject(nodeName),
					DNSNames: []string{"worker-1.internal", "worker-1.example.com"},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalDNS, Address: "worker-1.internal"},
				{Type: corev1.NodeExternalDNS, Address: "worker-1.example.com"},
			}}},
			want:       Approve,
			wantReason: ReasonApproved,
		},
		{
			name: "rule 9: case-insensitive + trailing-dot tolerance",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:  validBaselineSubject(nodeName),
					DNSNames: []string{"WORKER-1.cluster.local."},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeHostName, Address: "worker-1.cluster.local"},
			}}},
			want:       Approve,
			wantReason: ReasonApproved,
		},
		{
			name: "rule 9: DNS SAN not in node addresses",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:  validBaselineSubject(nodeName),
					DNSNames: []string{"attacker.example.com"},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeHostName, Address: "worker-1.cluster.local"},
			}}},
			want:       Deny,
			wantReason: ReasonDNSSANUnauthorized,
		},
		{
			name: "rule 9: DNS SAN matches a string of the wrong type",
			mutate: func(c *certv1.CertificateSigningRequest) {
				// Node has the same string "10.0.0.1" but as InternalIP — DNS
				// SANs must not match IP entries.
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:  validBaselineSubject(nodeName),
					DNSNames: []string{"10.0.0.1"},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			}}},
			want:       Deny,
			wantReason: ReasonDNSSANUnauthorized,
		},
		{
			name: "rule 9: wildcard SAN rejected",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:  validBaselineSubject(nodeName),
					DNSNames: []string{"*.cluster.local"},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeHostName, Address: "worker-1.cluster.local"},
			}}},
			want:       Deny,
			wantReason: ReasonDNSSANUnauthorized,
		},
		// ---- rule 10 --------------------------------------------------------
		{
			name: "rule 10: IPv4 SAN matches InternalIP",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:     validBaselineSubject(nodeName),
					IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			}}},
			want:       Approve,
			wantReason: ReasonApproved,
		},
		{
			name: "rule 10: IPv4 SAN matches ExternalIP",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:     validBaselineSubject(nodeName),
					IPAddresses: []net.IP{net.ParseIP("203.0.113.5")},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "203.0.113.5"},
			}}},
			want:       Approve,
			wantReason: ReasonApproved,
		},
		{
			name: "rule 10: IPv6 SAN matches",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:     validBaselineSubject(nodeName),
					IPAddresses: []net.IP{net.ParseIP("fd12:3456:789a::1")},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "fd12:3456:789a::1"},
			}}},
			want:       Approve,
			wantReason: ReasonApproved,
		},
		{
			name: "rule 10: IP SAN not in node addresses",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:     validBaselineSubject(nodeName),
					IPAddresses: []net.IP{net.ParseIP("192.0.2.99")},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			}}},
			want:       Deny,
			wantReason: ReasonIPSANUnauthorized,
		},
		{
			name: "rule 10: IP SAN matches Hostname-typed address (wrong type)",
			mutate: func(c *certv1.CertificateSigningRequest) {
				// Node Hostname happens to be "10.0.0.1" — IP SAN must not match it.
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:     validBaselineSubject(nodeName),
					IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeHostName, Address: "10.0.0.1"},
			}}},
			want:       Deny,
			wantReason: ReasonIPSANUnauthorized,
		},
		{
			name: "rule 10: one of two IPs unauthorized",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:     validBaselineSubject(nodeName),
					IPAddresses: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.99")},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			}}},
			want:       Deny,
			wantReason: ReasonIPSANUnauthorized,
		},
		// ---- rule 11 --------------------------------------------------------
		{
			name: "rule 11: email SAN forbidden",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:        validBaselineSubject(nodeName),
					EmailAddresses: []string{"admin@example.com"},
				})
			},
			want:       Deny,
			wantReason: ReasonForbiddenSANType,
		},
		{
			name: "rule 11: URI SAN forbidden",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject: validBaselineSubject(nodeName),
					URIs:    []*url.URL{{Scheme: "spiffe", Host: "example.com", Path: "/ns/foo/sa/bar"}},
				})
			},
			want:       Deny,
			wantReason: ReasonForbiddenSANType,
		},
		{
			name: "rule 11: both email and URI SANs forbidden",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:        validBaselineSubject(nodeName),
					EmailAddresses: []string{"admin@example.com"},
					URIs:           []*url.URL{{Scheme: "https", Host: "example.com"}},
				})
			},
			want:       Deny,
			wantReason: ReasonForbiddenSANType,
		},
		// ---- rule 12 --------------------------------------------------------
		{
			name: "rule 12: arbitrary unknown OID",
			mutate: func(c *certv1.CertificateSigningRequest) {
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject: validBaselineSubject(nodeName),
					ExtraExtensions: []pkix.Extension{
						{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 99}, Value: []byte{0x05, 0x00}},
					},
				})
			},
			want:       Deny,
			wantReason: ReasonUnknownExtension,
		},
		{
			name: "rule 12: BasicConstraints rejected (kubelet has no business asking)",
			mutate: func(c *certv1.CertificateSigningRequest) {
				// DER for BasicConstraints{CA: false}: SEQUENCE{} → 0x30 0x00.
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject: validBaselineSubject(nodeName),
					ExtraExtensions: []pkix.Extension{
						{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x00}},
					},
				})
			},
			want:       Deny,
			wantReason: ReasonUnknownExtension,
		},
		{
			name: "rule 12: SubjectAltName extension is allowed",
			mutate: func(c *certv1.CertificateSigningRequest) {
				// Real SAN — same path the rule-9 positive cases use.
				c.Spec.Request = mustCSRBytesFull(t, &x509.CertificateRequest{
					Subject:  validBaselineSubject(nodeName),
					DNSNames: []string{"worker-1.cluster.local"},
				})
			},
			node: &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeHostName, Address: "worker-1.cluster.local"},
			}}},
			want:       Approve,
			wantReason: ReasonApproved,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.skip != "" {
				t.Skip(c.skip)
			}
			csr := baselineCSR()
			c.mutate(csr)

			var node *corev1.Node
			switch {
			case c.nilNode:
				node = nil
			case c.node != nil:
				node = c.node
			default:
				node = validBaselineNode()
			}

			got, reason := Evaluate(csr, node)
			if got != c.want || reason != c.wantReason {
				t.Errorf("Evaluate = (%s, %s), want (%s, %s)",
					got, reason, c.want, c.wantReason)
			}
		})
	}
}
