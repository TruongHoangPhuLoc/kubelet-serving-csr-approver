# kubelet-csr-approver

A single-purpose Kubernetes controller that auto-approves
`kubernetes.io/kubelet-serving` CertificateSigningRequests, replacing the
manual approval toil while preserving the safety property that **no kubelet
can request a serving cert with SANs that don't match its real identity**.

This controller owns ONLY the approval gate. `kube-controller-manager`
continues to do the actual signing — we never touch the cluster CA key.

## How it works

When a kubelet's serving cert nears expiry it submits a CSR with
`signerName: kubernetes.io/kubelet-serving`. KCM signs once approved but does
not auto-approve, because the CSR's SANs are caller-supplied. This controller
applies a strict allowlist policy and approves only CSRs that pass.

A CSR is approved iff **every** rule below holds. Any miss → **Deny**, with a
reason naming the failed rule. **Fail closed**: in doubt, deny.

| #  | Rule                                                                                          |
|----|-----------------------------------------------------------------------------------------------|
| 1  | `spec.signerName == "kubernetes.io/kubelet-serving"`                                          |
| 2  | `spec.username == "system:node:<nodeName>"` (apiserver-set, root of trust)                    |
| 3  | `spec.groups` contains `system:nodes`                                                         |
| 4  | `spec.request` parses as PKCS#10 and the embedded self-signature verifies                     |
| 5  | parsed `Subject.CommonName == "system:node:<nodeName>"` (same `<nodeName>` as rule 2)         |
| 6  | parsed `Subject.Organization == ["system:nodes"]`                                             |
| 7  | `spec.usages` is exactly `{digital signature, key encipherment, server auth}` — no client auth |
| 8  | a `Node` named `<nodeName>` exists                                                            |
| 9  | every DNS SAN matches `node.status.addresses` of type `Hostname` / `InternalDNS` / `ExternalDNS` |
| 10 | every IP SAN matches `node.status.addresses` of type `InternalIP` / `ExternalIP`              |
| 11 | no `EmailAddress` or `URI` SANs                                                               |
| 12 | no unknown / unhandled X.509 extensions                                                       |

Two cross-cutting principles drive the design:

- **Trust only apiserver-set fields.** `spec.username` and `spec.groups` are
  filled by kube-apiserver from the authenticated identity — trustworthy.
  Everything inside `spec.request` is caller-controlled and must be
  cross-checked against the trusted identity.
- **No DNS resolution.** The Node object's `.status.addresses` is the only
  source of truth for valid SANs. DNS is mutable from outside the cluster.

## Status

All twelve policy rules are implemented and table-tested (positive + negative
cases per rule). The reconciler PATCHes the CSR's `/approval` subresource via
`CertificatesV1().UpdateApproval`. An `envtest`-based integration test in
`internal/controller/csr_controller_test.go` exercises the full code path
(approve / rule-8 deny / idempotency) against a real kube-apiserver. Plain
Kustomize manifests live in `deploy/`. Still missing: Prometheus metrics
(decision counts, pending CSRs, reconcile duration).

### Running envtest locally

```bash
go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
export KUBEBUILDER_ASSETS=$(setup-envtest use -p path 1.36.0)
go test -tags envtest ./internal/controller/...
```

CI runs the same flow on every PR.

## Project layout

```
cmd/kubelet-csr-approver/   # main: manager setup, flags, signal handling
internal/
  policy/                   # pure (CSR, Node) → (Decision, Reason); table-tested
  controller/               # CSR reconciler, predicate, node lookup
deploy/                     # plain Kustomize manifests (TODO)
.github/workflows/ci.yaml   # vet + test on PR/push; image build + GHCR push on tag
Dockerfile                  # multi-stage: golang builder → distroless static:nonroot
```

## Build & test

```bash
go vet ./...
go test ./...
go build ./cmd/kubelet-csr-approver
```

The Go toolchain auto-downloads (`go.mod` declares `go 1.26`).

## Operational principles

- **Stateless.** Pure decision function. No DB, no PVC. Restart-safe.
- **Single replica.** Approval is idempotent; on restart, pending CSRs are
  re-delivered as informer Add events. No leader election yet — revisit only
  if the cluster grows past ~100 nodes, short-lived kubelet certs are
  adopted, or the autoscaler creates nodes frequently.
- **Minimum RBAC.** Anything more is a bug:
  - `nodes`: get, list, watch
  - `certificatesigningrequests`: get, list, watch
  - `certificatesigningrequests/approval`: update
  - `signers` (resourceName `kubernetes.io/kubelet-serving`): approve
- **Observable.** `/healthz`, `/readyz`, `/metrics`; one structured log line
  per decision; metrics for decision counts, pending CSRs, reconcile
  duration.

## Learning the codebase

If you know Kubernetes but are new to Go controllers, start with
[`docs/walkthrough.md`](docs/walkthrough.md) — a guided tour of how the
control loop works, what each file does, the gotchas that confused the
author when learning this pattern, and a glossary.

## License

MIT — see [LICENSE](LICENSE).
