# Using kubelet-csr-approver

Operator's guide. If you want to *understand* how the control loop works
internally, read [`walkthrough.md`](walkthrough.md) first — this doc assumes
you just want to install, verify, run, and troubleshoot the thing.

---

## Contents

1. [What this controller does](#1-what-this-controller-does)
2. [The 12-rule policy](#2-the-12-rule-policy)
3. [Prerequisites](#3-prerequisites)
4. [Installing the controller](#4-installing-the-controller)
5. [Enabling kubelets to use it](#5-enabling-kubelets-to-use-it)
6. [Verifying the installation](#6-verifying-the-installation)
7. [Inspecting a CSR and its decision](#7-inspecting-a-csr-and-its-decision)
8. [Inspecting the issued serving cert](#8-inspecting-the-issued-serving-cert)
9. [Triggering certificate regeneration](#9-triggering-certificate-regeneration)
10. [Common denial reasons and what they mean](#10-common-denial-reasons-and-what-they-mean)
11. [Troubleshooting](#11-troubleshooting)
12. [Upgrading the controller](#12-upgrading-the-controller)
13. [Rollback](#13-rollback)
14. [Security model: what this does and doesn't protect](#14-security-model-what-this-does-and-doesnt-protect)
15. [Uninstall](#15-uninstall)

---

## 1. What this controller does

This is a single-purpose Kubernetes controller that auto-approves
`kubernetes.io/kubelet-serving` CertificateSigningRequests against a
strict 12-rule policy.

It owns **only the approval gate**. `kube-controller-manager` (KCM) is what
actually signs certificates — we never touch the cluster CA private key.

The safety property we preserve: **no kubelet can request a serving cert
with SANs that don't match its real identity.** The Node's
`.status.addresses` is the only source of truth for what SANs are allowed;
we never resolve DNS or trust caller-provided fields beyond what the
apiserver itself authenticated.

---

## 2. The 12-rule policy

A CSR is approved iff every rule below holds. Rules are checked in numeric
order; the first failure determines the denial reason.

| # | Rule | Denial reason |
|---|------|---|
| 1 | `spec.signerName == "kubernetes.io/kubelet-serving"` | `SignerMismatch` |
| 2 | `spec.username` matches `system:node:<nodeName>` | `UsernameInvalid` |
| 3 | `spec.groups` contains `system:nodes` | `NotInNodeGroup` |
| 4 | `spec.request` parses as PKCS#10 and self-signature verifies | `CSRParseError` |
| 5 | parsed `Subject.CommonName == "system:node:<nodeName>"` | `CommonNameMismatch` |
| 6 | parsed `Subject.Organization == ["system:nodes"]` | `OrganizationInvalid` |
| 7 | `spec.usages` contains `{server auth, digital signature}`, may include `key encipherment`, nothing else — no `client auth` | `UsagesInvalid` |
| 8 | a `Node` named `<nodeName>` exists | `NodeNotFound` |
| 9 | every DNS SAN matches `.status.addresses` of type `Hostname` / `InternalDNS` / `ExternalDNS` | `DNSSANUnauthorized` |
| 10 | every IP SAN matches `.status.addresses` of type `InternalIP` / `ExternalIP` | `IPSANUnauthorized` |
| 11 | no `EmailAddress` or `URI` SANs | `ForbiddenSANType` |
| 12 | no unknown / unhandled X.509 extensions | `UnknownExtension` |

Rule numbering corresponds to `Reason*` constants in
[`internal/policy/policy.go`](../internal/policy/policy.go).

---

## 3. Prerequisites

| Item | Requirement |
|---|---|
| Kubernetes version | 1.22+ (older may work; not tested) |
| Cluster CA | Whatever `kube-controller-manager` signs with — we don't manage it |
| KCM controllers running | At minimum `csrsigning`. `csrapproving` (the built-in approver for `kube-apiserver-client-kubelet` bootstrap CSRs) is required only if you also need automated client-cert bootstrapping. |
| Kubelet config | `serverTLSBootstrap: true` and `rotateCertificates: true` — see [§5](#5-enabling-kubelets-to-use-it) |
| RBAC | The Application's ServiceAccount needs the permissions in [`deploy/clusterrole.yaml`](../deploy/clusterrole.yaml) |
| Network | Pod needs to reach the apiserver; standard cluster networking |

The minimum RBAC is:

- `nodes`: `get`, `list`, `watch`
- `certificatesigningrequests`: `get`, `list`, `watch`
- `certificatesigningrequests/approval`: `update`
- `signers` resourceName `kubernetes.io/kubelet-serving`: `approve`

Anything broader is a bug.

---

## 4. Installing the controller

Three install paths, in order of friction:

### 4.1 Plain `kubectl apply` (quickest)

```bash
kubectl apply -k 'github.com/TruongHoangPhuLoc/kubelet-serving-csr-approver//deploy?ref=main'
```

This installs into `kube-system` with whatever the controller repo's
`deploy/deployment.yaml` currently pins (a `:latest` tag by default). Use
this only for trying it out — `:latest` is mutable and not reproducible.

### 4.2 Kustomize overlay (recommended)

In a Git-tracked directory of your own:

```yaml
# kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - 'github.com/TruongHoangPhuLoc/kubelet-serving-csr-approver//deploy?ref=main'

# Pin to a specific image tag for reproducibility. Bump after each green CI
# build on the controller repo.
images:
  - name: ghcr.io/truonghoangphuloc/kubelet-serving-csr-approver
    newTag: sha-cbc4434
```

Apply with `kubectl apply -k .`. This is the same shape the home-lab
ArgoCD overlay uses; see
[`platform/system/kubelet-csr-approver/`](https://github.com/TruongHoangPhuLoc/home-lab/tree/main/platform/system/kubelet-csr-approver)
for a live example.

### 4.3 ArgoCD Application

If your cluster is GitOps-managed, point an Application at the overlay
directory from §4.2. Example for the home-lab:
[`platform/system/kubelet-csr-approver/application.yaml`](https://github.com/TruongHoangPhuLoc/home-lab/blob/main/platform/system/kubelet-csr-approver/application.yaml).

Three things worth noting in that Application:

- `project: system` — scopes the destination to `kube-system` only.
- `automated.prune: false, selfHeal: false` initially. Flip both to `true`
  in a separate commit after 2–3 clean sync cycles.
- `syncOptions: ServerSideApply=true` — required for ArgoCD to co-manage
  resources with the controller-runtime's status writes without diff
  storms.

---

## 5. Enabling kubelets to use it

**Without this step, the controller has nothing to do.** By default,
kubelets generate a self-signed serving certificate at startup and never
submit a CSR.

On every node, edit `/var/lib/kubelet/config.yaml`:

```yaml
serverTLSBootstrap: true    # submit CSRs for serving certs
rotateCertificates: true    # also rotate the kubelet's client cert
```

Restart the kubelet to pick up the change:

```bash
sudo systemctl restart kubelet
```

The kubelet should submit a `kubernetes.io/kubelet-serving` CSR within
~5 seconds, which our controller will approve, KCM will sign, and the
kubelet will write to `/var/lib/kubelet/pki/kubelet-server-current.pem`.

**Rollout discipline:** flip one node first, verify it lands cleanly,
*then* do the rest. The first node always reveals at least one rough edge.

---

## 6. Verifying the installation

### 6.1 Pod is up

```bash
kubectl -n kube-system get pods -l app.kubernetes.io/name=kubelet-csr-approver
```

Expected: one `1/1 Running` pod.

### 6.2 Healthy startup logs

```bash
kubectl -n kube-system logs -l app.kubernetes.io/name=kubelet-csr-approver --tail=20
```

You should see lines like:

```
{"level":"info","msg":"starting manager"}
{"level":"info","msg":"Starting EventSource",...,"controllerKind":"CertificateSigningRequest"}
{"level":"info","msg":"Starting Controller",...,"controller":"kubelet-csr-approver"}
{"level":"info","msg":"Starting workers","worker count":1}
```

No `ERROR` lines, no `unable to ...` warnings.

### 6.3 RBAC is sufficient

```bash
kubectl auth can-i update certificatesigningrequests/approval \
  --as=system:serviceaccount:kube-system:kubelet-csr-approver
# expect: yes

kubectl auth can-i approve signers \
  --subresource=approve --resource-name=kubernetes.io/kubelet-serving \
  --as=system:serviceaccount:kube-system:kubelet-csr-approver
# expect: yes (Kubernetes 1.22+)
```

### 6.4 Health and readiness endpoints (port-forward)

```bash
POD=$(kubectl -n kube-system get pod -l app.kubernetes.io/name=kubelet-csr-approver -o jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system port-forward "$POD" 8081:8081 &
curl -s localhost:8081/healthz   # expect: ok
curl -s localhost:8081/readyz    # expect: ok
```

---

## 7. Inspecting a CSR and its decision

### 7.1 List CSRs and their decisions

```bash
kubectl get csr --sort-by=.metadata.creationTimestamp \
  -o custom-columns='NAME:.metadata.name,SIGNER:.spec.signerName,USER:.spec.username,CONDS:.status.conditions[*].type,AGE:.metadata.creationTimestamp' \
  | tail -20
```

A healthy kubelet-serving CSR ends with `CONDS = Approved,Issued`. A
controller-denied one ends with `CONDS = Denied`. A genuinely-pending
one has empty `CONDS`.

### 7.2 Read the controller's verdict for one CSR

The denial reason lives on the condition itself:

```bash
kubectl get csr <csr-name> -o jsonpath='{.status.conditions[*].reason}{"\n"}'
# e.g.: UsagesInvalid
```

For the full message including who decided it:

```bash
kubectl get csr <csr-name> -o jsonpath='{range .status.conditions[*]}{.type}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}'
```

### 7.3 Decode the PKCS#10 to inspect what the kubelet sent

```bash
kubectl get csr <csr-name> -o jsonpath='{.spec.request}' \
  | base64 -d \
  | openssl req -in - -noout -text \
  | head -25
```

What to look at:

- **`Subject:`** — should be `O = system:nodes, CN = system:node:<your-node-name>`. CN mismatch → rule 5 fired.
- **`Public Key Algorithm`** — modern kubelets use `id-ecPublicKey` / `NIST CURVE: P-256`.
- **`X509v3 Subject Alternative Name`** — these are the SANs being requested. Cross-reference against the Node's `.status.addresses`.

### 7.4 See what the kubelet asked for in `spec.usages`

```bash
kubectl get csr <csr-name> -o jsonpath='{.spec.usages}'; echo
```

Modern kubelet (ECDSA): `["digital signature","server auth"]`. Older
kubelet (RSA): includes `"key encipherment"`. Both shapes are accepted.

### 7.5 See what `.status.addresses` are on the Node

For comparing against the CSR's SANs:

```bash
kubectl get node <node-name> -o jsonpath='{range .status.addresses[*]}{.type}{"\t"}{.address}{"\n"}{end}'
```

Every SAN in the CSR must match an address of the right *type* (DNS to
`Hostname`/`InternalDNS`/`ExternalDNS`, IP to `InternalIP`/`ExternalIP`).

---

## 8. Inspecting the issued serving cert

Once the CSR is approved and KCM signs, the kubelet writes the cert to
`/var/lib/kubelet/pki/`. On the node:

```bash
sudo ls -la /var/lib/kubelet/pki/kubelet-server-*

# Decode the current cert:
sudo openssl x509 -in /var/lib/kubelet/pki/kubelet-server-current.pem -noout -text \
  | head -25
```

What to verify:

- **Subject:** matches `CN=system:node:<nodename>, O=system:nodes`.
- **Issuer:** your cluster CA.
- **Validity:** typically 1 year (`Not After` is now + ~365d on most setups).
- **X509v3 Subject Alternative Name:** matches what you allowed in the
  Node's `.status.addresses`.
- **X509v3 Extended Key Usage:** `TLS Web Server Authentication` only.
  *No `TLS Web Client Authentication`* — if that's present, something
  upstream is wrong.

You can also pull the cert out of the CSR object itself (the apiserver
stores it in `status.certificate`):

```bash
kubectl get csr <csr-name> -o jsonpath='{.status.certificate}' \
  | base64 -d \
  | openssl x509 -in - -noout -text \
  | head -25
```

---

## 9. Triggering certificate regeneration

Useful for testing the full flow without waiting a year for the cert to
expire.

### 9.1 Server cert only — clean and safe

On the node:

```bash
sudo rm /var/lib/kubelet/pki/kubelet-server-*
sudo systemctl restart kubelet
```

The kubelet detects the missing serving cert, generates a fresh keypair,
submits a new `kubernetes.io/kubelet-serving` CSR. Our controller picks it
up within seconds.

Watch from your workstation:

```bash
kubectl -n kube-system logs -l app.kubernetes.io/name=kubelet-csr-approver --tail=5 -f
# and in another terminal:
kubectl get csr -w | grep kubelet-serving
```

### 9.2 Server AND client cert — recovery path

If you also delete `kubelet-client-current.pem`, the kubelet loses the
identity it uses to authenticate to the apiserver. It falls back to its
`bootstrap-kubeconfig` (typically `/etc/kubernetes/bootstrap-kubelet.conf`)
and submits TWO CSRs in sequence:

1. `kubernetes.io/kube-apiserver-client-kubelet` — **NOT our signer.**
   Handled by KCM's built-in `csrapproving` controller if your cluster
   has the appropriate bootstrap auto-approval ClusterRoleBinding. If
   not, you'll need to manually `kubectl certificate approve`.
2. `kubernetes.io/kubelet-serving` — our controller approves this.

The client CSR must succeed first; without it, the kubelet can't auth to
post the serving CSR.

If you get stuck at step 1, manually approve:

```bash
kubectl certificate approve <client-csr-name>
```

…and then investigate why your bootstrap auto-approver isn't running.
Check kube-controller-manager's `--controllers=...` flag.

---

## 10. Common denial reasons and what they mean

When a CSR is denied, `status.conditions[0].reason` is one of these. Here's
the operator's quick reference:

| Reason | What it means | Most likely cause | Fix |
|---|---|---|---|
| `SignerMismatch` | The CSR isn't for our signer. We should never see this — the predicate filters them out before they reach `Reconcile`. | Defensive check fired. Treat as a code bug. | Open an issue with the CSR's `spec.signerName`. |
| `UsernameInvalid` | `spec.username` doesn't start with `system:node:` or has nothing after it. | A non-kubelet identity tried to submit a kubelet-serving CSR. | Investigate who's submitting. Could be a misconfigured automation or an actual incident. |
| `NotInNodeGroup` | `spec.groups` doesn't include `system:nodes`. | Same as `UsernameInvalid` — wrong identity. | Same: investigate. |
| `CSRParseError` | `spec.request` doesn't decode as valid PKCS#10, or the self-signature doesn't verify. | Malformed CSR; or signature tampered. Real kubelets don't produce these. | Inspect `spec.request` (`base64 -d \| openssl req`); discover what's malformed. If it's persistent and from a real kubelet, file a kubelet bug. |
| `CommonNameMismatch` | The CSR's `Subject.CommonName` doesn't match the trusted `system:node:<X>` from the username. | A kubelet authenticated as node A trying to mint a cert with CN claiming node B. | This is what rule 5 exists for. Investigate the source machine — it's either misconfigured or actively impersonating. |
| `OrganizationInvalid` | `Subject.Organization` isn't exactly `["system:nodes"]`. | Misconfigured kubelet, or an attempt to inject extra organisations. | Check the kubelet's bootstrap configuration. |
| `UsagesInvalid` | `spec.usages` doesn't satisfy rule 7. | Either missing `server auth` / `digital signature`, contains `client auth`, contains duplicates, or contains an unknown usage. | Run `kubectl get csr <name> -o jsonpath='{.spec.usages}'` to see what was sent. If it's a valid kubelet shape we don't yet support, open an issue with the output. |
| `NodeNotFound` | No `Node` object exists with the trusted nodeName. | Node was deleted but kubelet still alive, OR the kubelet submitted a CSR before its Node object existed (registration race). | If permanent: that node has been evicted and shouldn't have a fresh cert anyway. If transient: kubelet will retry once the Node lands. |
| `DNSSANUnauthorized` | A DNS SAN in the CSR doesn't match the Node's `.status.addresses`. | Kubelet asked for a hostname that the Node's status doesn't claim. | Cross-check `kubectl get node <name> -o jsonpath='{.status.addresses}'` against the CSR's SANs. Often a hostname mismatch from `--hostname-override` not aligning with `kubelet`'s node-name. |
| `IPSANUnauthorized` | Same, for IPs. | Often: kubelet wants its public IP but the Node's status only carries the internal IP. Or: the Node hasn't reported addresses yet. | Verify cloud-provider integration is reporting all expected addresses; or restrict the kubelet to only request IPs that are reported. |
| `ForbiddenSANType` | CSR has Email or URI SAN. | A kubelet shouldn't ever request these. Investigate. | Inspect the PKCS#10. |
| `UnknownExtension` | CSR has a PKCS#10 extension other than SubjectAltName. | A kubelet shouldn't set BasicConstraints, KeyUsage extension, or anything else. | Inspect the PKCS#10. |

---

## 11. Troubleshooting

### 11.1 Symptom: pending CSRs, no log activity from the controller

```bash
kubectl get csr | grep kubelet-serving       # several Pending, no Approved/Denied
kubectl -n kube-system logs -l app.kubernetes.io/name=kubelet-csr-approver --tail=20
# → no "csr decision applied" lines at all
```

Possibilities:

- **Pod isn't running.** `kubectl get pods -n kube-system -l app.kubernetes.io/name=kubelet-csr-approver`.
- **RBAC is broken.** The pod *is* running but its logs show
  `Forbidden` errors. Recheck §6.3.
- **Predicate is dropping events.** Unlikely, but possible if the CSR's
  `spec.signerName` doesn't match exactly. Verify with
  `kubectl get csr <name> -o jsonpath='{.spec.signerName}'`.

### 11.2 Symptom: deny loop on one node

```bash
kubectl -n kube-system logs -l app.kubernetes.io/name=kubelet-csr-approver --tail=20
# → repeated "csr decision applied ... decision=Deny reason=<X>"
```

This is the controller working — it just keeps refusing this kubelet's
CSRs, and the kubelet keeps creating new ones on its retry timer.

1. Read the `reason` field from the log.
2. Cross-reference §10 to learn what that rule failure means.
3. Inspect the offending CSR (§7) to see exactly what's wrong.
4. Fix the underlying cause (Node addresses, kubelet config, etc.).

Until the fix lands, the kubelet keeps serving with its *previous*
cert if it has one. No operational damage; the deny loop is annoying
but safe.

### 11.3 Symptom: pod is `CrashLoopBackOff`

```bash
kubectl -n kube-system logs -l app.kubernetes.io/name=kubelet-csr-approver --previous
```

Common causes:

- Missing RBAC (`Forbidden` errors at startup).
- Misconfigured `--metrics-bind-address` or `--health-probe-bind-address` flags.
- Image pull failure (different error — `ImagePullBackOff`, not `CrashLoopBackOff`).

### 11.4 Symptom: `ImagePullBackOff`

```bash
kubectl -n kube-system describe pod -l app.kubernetes.io/name=kubelet-csr-approver | tail -30
```

- Tag doesn't exist on the registry yet (you bumped `images.newTag` before
  CI finished publishing). Wait for CI, or roll back the tag bump.
- Registry is unreachable from your cluster. Check imagePullSecrets,
  network egress, ghcr.io reachability.

### 11.5 Symptom: KCM approves the CSR but the cert never appears on the node

Our job ends at `Approved`. The cert flow continues:

1. KCM's `csrsigning` controller signs and fills `status.certificate`.
2. Kubelet downloads, writes to disk.

If step 1 fails:

```bash
kubectl -n kube-system logs -l component=kube-controller-manager --tail=200 | grep -i csr
```

If step 2 fails:

```bash
ssh <node> sudo journalctl -u kubelet -n 100 | grep -iE 'certif|TLS|bootstrap'
```

---

## 12. Upgrading the controller

Two independent dimensions:

### 12.1 Image tag (the binary)

Most upgrades are this — a new build of the same shape.

In your kustomization overlay:

```yaml
images:
  - name: ghcr.io/truonghoangphuloc/kubelet-serving-csr-approver
    newTag: sha-<new-short-sha>
```

Bump `newTag` after every green CI run on the controller repo. ArgoCD
(or `kubectl apply`) rolls the pod within ~30s. The new pod's logs
should show its commit at startup; verify in
`kubectl describe pod -n kube-system -l app.kubernetes.io/name=kubelet-csr-approver`.

### 12.2 Manifest version (Deployment shape, RBAC)

If you changed the remote-base `?ref=` parameter (new tag, new commit
pinning the manifests), apply the same way. Restart isn't always needed —
RBAC and SA changes are applied without disturbing the pod.

### 12.3 Rolling out cautiously

The controller is single-replica, idempotent, and stateless. During an
upgrade rollout there's a brief window (~few seconds) where no controller
is running. CSRs created during that window will be processed when the
new pod comes up — informer Adds re-deliver pending CSRs on startup.

If you don't want even those few seconds of unavailability, run two
replicas and turn on leader election (`--leader-elect=true` and update
deploy/deployment.yaml to add a Lease). For most homelabs the
single-replica default is fine.

---

## 13. Rollback

If a new version misbehaves:

1. **Image rollback:** flip `images.newTag` back to the previous `sha-<X>`
   and reapply. ArgoCD rolls the pod within ~30s.
2. **Manifest rollback:** revert the `?ref=` to the previous SHA.
3. **Worst case:** delete the Application / `kubectl delete -k .` and
   let kubelets keep using their existing serving certs until you've
   diagnosed.

Kubelets that have valid serving certs are unaffected by the controller
being absent. The cost of a few hours of controller downtime is "no new
certs get approved during that window" — which only matters if you have
nodes joining or certs expiring.

---

## 14. Security model: what this does and doesn't protect

### 14.1 What we prevent

- **Cross-node impersonation via CSR.** A kubelet authenticated as node A
  cannot mint a serving cert claiming any aspect of node B. Rule 5 (CN
  matches trusted nodeName) is the cross-check.
- **Serving certs that are secretly client certs.** Rule 7's allowlist
  rejects `client auth` and any other surprise EKU.
- **SAN smuggling.** Rules 9–11 ensure every SAN was registered on the
  Node by whatever authority creates Nodes (kubelet registration,
  cluster-api, etc.). DNS is never resolved — the Node is the only source
  of truth.
- **Hostile X.509 extensions.** Rule 12 rejects anything outside the
  single accepted extension (SubjectAltName).

### 14.2 What we don't prevent

- **A compromised kubelet operating with its existing cert.** We sit at
  cert issuance; we don't revoke existing certs or detect runtime
  abuse. Cluster CA rotation is the lever for that, and it's
  out of scope for this controller.
- **A compromised Node Authorizer.** If something else creates Node
  objects with attacker-controlled addresses, our SAN allowlist would
  accept them. The integrity of `.status.addresses` is upstream of us.
- **Replay of an old valid CSR.** Each CSR is signed by the requesting
  kubelet's key, and KCM signs with a freshly-generated certificate. We
  don't store anything stateful, so we can't detect replays.
- **Bootstrap-token abuse for the *client* cert.** Our controller doesn't
  see the `kubernetes.io/kube-apiserver-client-kubelet` flow at all.
  Whatever protects bootstrap token issuance (TokenAuth, TLS bootstrap
  approval) handles that.

### 14.3 The trust root, plainly

We trust **exactly two things**:

1. The apiserver's authentication of the requester — `spec.username` and
   `spec.groups` are filled in by the apiserver based on the TLS identity
   of whoever POSTed the CSR. The client cannot lie about these.
2. The cluster operator's ownership of Node objects — `.status.addresses`
   is the registered identity of a node, and it's what we use to vet SANs.

Everything inside `spec.request` (the PKCS#10) is caller-controlled and
gets cross-checked against (1) and (2) before we approve.

---

## 15. Uninstall

```bash
kubectl delete -k .                # from your kustomize overlay directory
# or:
kubectl delete -k 'github.com/TruongHoangPhuLoc/kubelet-serving-csr-approver//deploy?ref=main'
```

Existing kubelets keep serving with their current certs until they expire.
Nodes that try to renew after the controller is gone will have
`Pending` CSRs that sit until something approves them (manual
`kubectl certificate approve`, a different approver, or this controller
re-installed).

If you want to also disable the CSR submission path: set
`serverTLSBootstrap: false` in each kubelet's config and restart. Each
kubelet will generate a self-signed cert at next start.

---

## Where to go next

- [`walkthrough.md`](walkthrough.md) — internals: control loop, codebase tour, glossary.
- [`internal/policy/policy.go`](../internal/policy/policy.go) — the actual rules, one function.
- [GitHub Issues](https://github.com/TruongHoangPhuLoc/kubelet-serving-csr-approver/issues) — feature ideas, bugs, denied CSR shapes we should accept.
