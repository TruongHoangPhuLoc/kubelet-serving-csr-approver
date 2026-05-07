# Walkthrough: how this controller works

You already know Kubernetes — CSRs, kubelets, Nodes, RBAC, signers, all of it.
What you're newer to is **Go** and **controller-runtime** (the framework most
Kubernetes controllers are built on). This document is a guided tour of the
codebase from that angle: what each piece does, why it's there, and the things
that tripped me up the first time.

It's not a reference manual. Read it once, then come back to specific sections
when something confuses you in the code.

---

## 1. The control loop in 60 seconds

This is the mental model everything else hangs off of:

```
   ┌────────────┐      watch events     ┌──────────┐
   │ apiserver  │  ─────────────────▶   │ informer │
   └────────────┘                       │  + cache │
        ▲                               └────┬─────┘
        │ Update / Patch                     │ Add/Update/Delete
        │                                    ▼
        │                              ┌──────────┐
        │                              │ predicate│  (filter: skip irrelevant events)
        │                              └────┬─────┘
        │                                   │
        │                                   ▼
        │                              ┌──────────┐
        │                              │ workqueue│  (deduplicates by name)
        │                              └────┬─────┘
        │                                   │ pop
        │                                   ▼
        │                              ┌──────────┐
        └──────────────────────────────│Reconcile │  ←  your code
                                       └──────────┘
```

Key properties:

- **Eventually consistent.** Reconcile says "given the current state of object
  X, drive the world toward the desired state." It does not assume any
  particular trigger fired it. It can run again at any time, and that has to
  be safe (idempotent).
- **One worker per controller** by default. That's why we don't need locks
  inside Reconcile.
- **The cache is your friend.** Reads from `r.Get` come from the local
  informer cache, not the apiserver — fast, no rate-limit worries.
- **Errors retry.** If Reconcile returns an error, controller-runtime
  requeues with exponential backoff. So "I don't know what's wrong, let it
  retry" is a totally valid strategy.

If this picture doesn't fit yet, re-read it after the next two sections.

---

## 2. The codebase in execution order

When you run `kubelet-csr-approver`, control flows roughly:

```
main.go  ─▶  manager  ─▶  predicate  ─▶  Reconcile  ─▶  policy.Evaluate  ─▶  applyDecision
```

Each step:

### 2.1 `cmd/kubelet-csr-approver/main.go` — process startup

Three things happen here:

1. **Build a `scheme`.** A scheme is a map "this Go type ↔ this Kubernetes
   GVK (Group/Version/Kind)". `clientgoscheme.AddToScheme(scheme)` registers
   every built-in type — Node, CSR, Pod, etc. controller-runtime needs this
   to know how to encode/decode the objects you watch.

2. **Build a `manager`.** The manager is controller-runtime's god object.
   It owns the cache, the informers, the metrics server, the health probes,
   leader election, and signal handling. You configure it once and hand it
   to your controller(s).

3. **Register the controller and start.** `controller.SetupWithManager(mgr)`
   tells the manager "watch CSRs, run my reconciler on each event."
   `mgr.Start(ctx)` runs forever.

The manager construction reads:

```go
mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
    Scheme: scheme,
    Metrics: metricsserver.Options{BindAddress: metricsAddr},
    HealthProbeBindAddress: probeAddr,
    LeaderElection: leaderElect,
    ...
})
```

`ctrl.GetConfigOrDie()` is "find a kubeconfig however you can — in-cluster
service account, `KUBECONFIG` env var, `~/.kube/config` — and panic if you
can't." That single function is why this binary "just works" both inside a
pod and on your laptop.

### 2.2 `SetupWithManager` — wiring the controller

Look at `internal/controller/csr_controller.go`:

```go
return ctrl.NewControllerManagedBy(mgr).
    Named(controllerName).
    For(&certv1.CertificateSigningRequest{}, builder.WithPredicates(kubeletServingPredicate())).
    Complete(&CSRReconciler{Client: mgr.GetClient(), Clientset: clientset})
```

This is a builder pattern. It says:

- This controller is **named** `kubelet-csr-approver` (shows up in metrics).
- It **For**s a `CertificateSigningRequest` — i.e., it watches CSRs as the
  primary resource type. (You can also `Owns()` secondary types, but we
  don't here.)
- It uses a **predicate** (filter) to ignore most events.
- It **Completes** with our `CSRReconciler` — the thing whose `Reconcile`
  method gets called.

Behind the scenes, the manager will spin up an informer for CSRs, plumb
events through the predicate, then enqueue them for Reconcile.

### 2.3 The predicate — early filter

```go
func kubeletServingPredicate() predicate.Predicate { ... }
```

The predicate runs **on every event**, before anything is queued. We use it
to drop events we don't care about:

- `signerName != "kubernetes.io/kubelet-serving"` — not our signer.
- `len(status.conditions) > 0` — already decided.

Why bother? Because without a predicate, every CSR in the cluster (including
ones for other signers) would be queued for Reconcile. That's wasted work.
Filtering at the predicate level keeps the queue tight.

⚠️ **The predicate is an optimization, not a security boundary.** Our
Reconcile re-checks both conditions defensively. You should always write
Reconcile as if the predicate didn't exist — predicates can be bypassed by
cache resyncs or programmer error.

### 2.4 `Reconcile` — your code

This is the heart of the controller. Read the function in
`internal/controller/csr_controller.go`. The shape is:

```go
func (r *CSRReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
    // 1. Fetch the object by name.
    var csr certv1.CertificateSigningRequest
    if err := r.Get(ctx, req.NamespacedName, &csr); err != nil {
        if apierrors.IsNotFound(err) {
            return reconcile.Result{}, nil   // already deleted; nothing to do
        }
        return reconcile.Result{}, err       // transient error; retry
    }

    // 2. Re-check defensive invariants.
    if csr.Spec.SignerName != policy.KubeletServingSignerName { return ... }
    if len(csr.Status.Conditions) > 0 { return ... }

    // 3. Fetch related objects you need.
    var node *corev1.Node
    if name, ok := nodeNameFromUsername(csr.Spec.Username); ok {
        // r.Get into &n; node-not-found leaves node = nil
    }

    // 4. Decide.
    decision, reason := policy.Evaluate(&csr, node)

    // 5. Write back.
    if err := r.applyDecision(ctx, &csr, decision, reason); err != nil {
        return reconcile.Result{}, err
    }
    return reconcile.Result{}, nil
}
```

This is the canonical shape of every controller-runtime reconcile. Memorise
it. **Fetch, decide, write back, return.**

A few specifics worth noting:

- **`req.NamespacedName`** identifies the object — not the object itself.
  CSRs are cluster-scoped so the namespace is empty; for namespaced
  resources you'd get both name and namespace.
- **`apierrors.IsNotFound`** — returning `nil, nil` for not-found is
  important: object was deleted between event and reconcile, no work to do.
  Returning the error would cause an infinite retry storm.
- **`reconcile.Result{}`** zero-value means "done, don't requeue." You can
  also return `{RequeueAfter: 30 * time.Second}` to be re-run after a delay.

### 2.5 `policy.Evaluate` — pure decision logic

`internal/policy/policy.go`. This is just a Go function:

```go
func Evaluate(csr *certv1.CertificateSigningRequest, node *corev1.Node) (Decision, Reason)
```

No client calls. No `context.Context`. No logging. No DNS resolution. Just
inputs → output.

Why so disciplined? Because **pure functions are dramatically easier to
test**. We have 41 table tests in `policy_test.go` that run in milliseconds
because none of them needs an apiserver. If `Evaluate` had been allowed to
do `r.Get` calls, every test would need an envtest harness. By keeping the
side effects out, we collapse the tested-thing down to "given these inputs,
do you produce that output?".

This pattern is not unique to controllers — it's just the "core / shell"
or "functional core, imperative shell" architecture from broader software
design, applied here. The reconciler is the *imperative shell* (talks to
the world); `Evaluate` is the *functional core* (decides things).

### 2.6 `applyDecision` — write-back via `/approval`

After `Evaluate`, we have to actually approve or deny. That means appending
a condition to `csr.Status.Conditions` and PATCHing the CSR's `/approval`
**subresource**.

A subresource is a sub-endpoint on a resource. For CSRs:

- `/csr/<name>` — the main resource. RBAC verbs `get`, `list`, `watch`,
  `update`, etc.
- `/csr/<name>/approval` — the approval subresource. Only changes to
  `status.conditions` are accepted; everything else is ignored.
- `/csr/<name>/status` — full status subresource (we don't use it).

The `/approval` subresource is special: it's the agreed-on way for an
approver to set Approved/Denied conditions, and it requires the
`certificatesigningrequests/approval` `update` permission **plus** the
`signers/approve` permission for the specific signer name. That's why
the ClusterRole has both rules — they're not redundant.

In code, the call is:

```go
r.Clientset.CertificatesV1().CertificateSigningRequests().
    UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
```

`UpdateApproval` is generated specifically for this subresource by Kubernetes'
client-gen tool. It's an HTTP `PUT` to `/csr/<name>/approval` with the full
CSR as the body — the apiserver looks only at status.conditions and ignores
the rest.

---

## 3. Walkthrough: what happens when a kubelet posts a CSR

Let's trace one end-to-end. Suppose `worker-1`'s kubelet wants a fresh
serving cert.

**T+0** — Kubelet sends `POST /apis/certificates.k8s.io/v1/certificatesigningrequests`
with a CSR object. Spec includes `signerName=kubernetes.io/kubelet-serving`
and a PKCS#10 blob in `spec.request`. The apiserver overwrites
`spec.username` with `system:node:worker-1` (taken from the kubelet's
authenticated TLS identity), `spec.groups` with the kubelet's groups, and
clears any client-set status. CSR persists in etcd.

**T+1ms** — Our informer's watch sees a new CSR. It updates the local cache
and fires an Add event.

**T+1ms** — `kubeletServingPredicate.CreateFunc` runs. It checks signerName
and conditions — both pass — so it returns `true`. The event handler
enqueues a `reconcile.Request{Name: csr.Name}` onto the workqueue.

**T+2ms** — A reconcile worker pops the item. controller-runtime calls
`CSRReconciler.Reconcile(ctx, req)`.

**T+2ms** — Reconcile calls `r.Get` against the cache, gets the CSR back.
Defensive re-checks pass. It extracts the node name from `spec.username`,
calls `r.Get` for `Node{Name: "worker-1"}`. Hit — node is in the cache.

**T+2ms** — Reconcile calls `policy.Evaluate(&csr, node)`. The policy:
1. Signer matches → continue.
2. Username `system:node:worker-1` parses → nodeName=`worker-1`.
3. Groups contains `system:nodes` → continue.
4. PKCS#10 parses, signature verifies → continue. We now hold the parsed
   `*x509.CertificateRequest` (`cr`).
5. `cr.Subject.CommonName == "system:node:worker-1"` → continue.
6. `cr.Subject.Organization == ["system:nodes"]` → continue.
7. Usages set is exactly `{digital signature, key encipherment, server auth}` → continue.
8. node is non-nil → continue.
9. Each `cr.DNSNames` entry is in `node.Status.Addresses{Hostname,InternalDNS,ExternalDNS}` → continue.
10. Each `cr.IPAddresses` entry is in `node.Status.Addresses{InternalIP,ExternalIP}` → continue.
11. `cr.EmailAddresses` and `cr.URIs` are empty → continue.
12. No unknown extensions → continue.

Returns `(Approve, ReasonApproved)`.

**T+3ms** — `applyDecision`:
- DeepCopy the CSR.
- Append `CertificateSigningRequestCondition{Type: Approved, Reason: "Approved", ...}`.
- Call `clientset.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, ...)`.

**T+5ms** — apiserver writes the new condition to etcd.

**T+5ms** — `kube-controller-manager`'s CSR signer (a DIFFERENT controller,
not us) is also watching CSRs. It sees the Approved condition land. It
signs the cert with the cluster CA, fills `csr.status.certificate`, and
PATCHes that.

**T+10ms** — Kubelet's CSR submitter sees `status.certificate` populated.
It downloads, writes to disk, restarts its TLS listener. Done.

**T+12ms** — Our controller's informer also sees the update from KCM. The
predicate now sees `len(conditions) > 0` and drops the event. No reconcile
fires. We're done.

Total: ~10ms wall-clock for a happy path on a healthy cluster.

---

## 4. Things that confused me when I started

### "Why two different clients?"

The reconciler has both `client.Client` (from controller-runtime) and
`kubernetes.Interface` (the typed clientset from `client-go`). Why?

- **`client.Client`** is the cache-backed reader/writer. Its reads are
  served by the local informer cache (fast, free), and its writes go to the
  apiserver. It's generic — `client.Get(ctx, name, &someObj)` works for any
  registered type. **Use it for reads.**

- **`kubernetes.Interface`** is the strongly-typed clientset, generated by
  Kubernetes' code generator. Reads always hit the apiserver (no cache).
  But it has methods for **subresources** (`UpdateApproval`,
  `EvictPodWithPolicy`, etc.) that the generic `client.Client` doesn't
  expose as cleanly. **Use it for subresource writes.**

You can do everything with one or the other if you really want, but the
split is the conventional pattern: one cached generic client for the hot
read path, one typed clientset for the well-known write paths.

### "Why DeepCopy before mutating?"

```go
toUpdate := csr.DeepCopy()
toUpdate.Status.Conditions = append(toUpdate.Status.Conditions, cond)
```

The object you get back from `r.Get` lives in the same memory the cache
might also be reading from. Mutate it directly and another goroutine
(another reconcile, another watch handler) might see your half-finished
mutation. `DeepCopy` makes you a private copy.

This pattern is so universal in Kubernetes Go code that every API type has
a generated `DeepCopy()` method. Use it whenever you're about to change
fields on something `r.Get` returned.

### "What is `context.Context`?"

`ctx` is Go's standard mechanism for **cancellation and deadlines**. When
the manager shuts down (e.g. SIGTERM), it cancels the context. Any function
that takes a `ctx context.Context` should periodically check it and bail
out cleanly.

Most Kubernetes API calls take a `ctx` and respect it — if you cancel,
in-flight HTTP requests are torn down. You almost always just thread the
incoming `ctx` through and let the underlying clients do the right thing.

For background, `ctx.Done()` returns a channel that closes when the context
is cancelled. You'll see code patterns like:

```go
select {
case <-ctx.Done():
    return ctx.Err()
case <-someOtherChannel:
    ...
}
```

In Reconcile, you almost never write that yourself — the API clients
handle it.

### "The apiserver overwrites `spec.username` on CSR create?"

Yes. This caught me when writing the envtest tests. When a client POSTs a
CSR, the apiserver fills `spec.username`, `spec.uid`, and `spec.groups`
from the **requester's authenticated identity**, regardless of what the
client sent. This is what makes those fields trustworthy — a client can't
lie about who it is.

The implication for the envtest test: to get a CSR with
`spec.username == "system:node:worker-1"`, the test client has to actually
authenticate as that identity. We do that with **impersonation** — the
admin client tells the apiserver "for this request, pretend I'm
system:node:worker-1". See `nodeClient(t, nodeName)` in the integration
test.

In production, this is why rule 2 (username check) is the root of trust.
Everything inside the PKCS#10 blob is caller-controlled; only fields the
apiserver sets are trustworthy.

### "Why have both a predicate AND defensive checks in Reconcile?"

The predicate is performance — drop irrelevant events before they hit the
queue. The defensive checks are correctness — never trust that the
predicate ran, because:

- A `cache resync` event can fire Reconcile without the predicate running
  for that specific path.
- A future maintainer might break the predicate.
- An object's spec can change between when the predicate ran and when
  Reconcile picks it up.

Predicates make things faster; defensive checks make things correct.
Always have both.

### "What's a build tag and why does the envtest test have one?"

```go
//go:build envtest
```

That line at the top of `csr_controller_test.go` is a Go build constraint.
The file is only compiled when you pass `-tags envtest` to the Go tool.
Without the tag, `go test ./...` skips the file entirely.

Why? Because envtest needs binaries (`kube-apiserver`, `etcd`) that have to
be downloaded with `setup-envtest`. If we left the test always-on, every
contributor who hadn't run `setup-envtest` would see the test fail with a
confusing error. With the tag, `go test ./...` is fast and clean by
default; the integration test runs explicitly when you ask for it.

CI runs both jobs: a fast `test` job without the tag, and a slow `envtest`
job with the binaries installed.

---

## 5. Glossary (terms that show up everywhere)

- **Manager** — controller-runtime's god object. Owns the cache, informers,
  metrics server, health probes, leader election. You build one and hand
  it your controllers.

- **Scheme** — registry mapping Go types to Kubernetes GVKs (Group/Version/
  Kind). Required so the manager knows how to serialise things.

- **Informer** — long-lived watcher of a resource type. Maintains a local
  in-memory cache and fires events on change. Built by the manager when
  you say `For(&Foo{})`.

- **Cache** — the local store fed by informers. `client.Client.Get` reads
  from it.

- **Reconciler** — your code; the thing with a `Reconcile` method.

- **Predicate** — filter on informer events. Decides whether an event
  becomes a reconcile request.

- **Workqueue** — deduplicating queue between informer events and
  reconcilers. If the same object's name is enqueued twice while one
  reconcile is in flight, the second is coalesced.

- **Subresource** — sub-endpoint on a resource. `/status`, `/scale`,
  `/approval`, etc. Each has its own RBAC verb permissions.

- **GVK / GVR** — Group/Version/Kind (Go side, e.g. `apps/v1, Deployment`)
  vs. Group/Version/Resource (REST side, e.g. `apps/v1, deployments`). You
  see GVK in the scheme; GVR in REST URLs and RBAC rules.

- **DeepCopy** — generated method on every API type. Makes a private copy
  before you mutate anything `r.Get` returned.

- **`client.Client`** — controller-runtime's generic, cache-backed client.

- **Clientset (`kubernetes.Interface`)** — code-generated, strongly-typed
  client from `client-go`. Has subresource methods.

- **envtest** — controller-runtime's test harness that runs a real
  `kube-apiserver` + `etcd` for integration tests. No kubelet, no other
  controllers — just the API surface.

- **Impersonation** — the apiserver feature that lets a privileged client
  say "for this request, pretend I'm someone else." Requires the
  `impersonate` verb. We use it in tests to post CSRs as `system:node:*`.

- **Idempotency** — running the same code on the same input produces the
  same result. Critical for reconcilers because controller-runtime can re-
  invoke Reconcile any time.

- **Leader election** — when running multiple controller replicas, only
  one holds a lock and runs reconciles. We currently use single-replica
  with leader-elect=false.

---

## 6. What to read next

When you want to go deeper:

- **The Kubebuilder Book** — https://book.kubebuilder.io/. Despite our
  not using kubebuilder for scaffolding, the explanatory chapters
  (especially "Architecture Concept Diagram" and "Implementing a
  Controller") are the best free intro to controller-runtime.

- **`sigs.k8s.io/controller-runtime/pkg/client` docs** —
  https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/client. The
  client.Client interface is small; reading the godoc takes 10 minutes
  and demystifies a lot.

- **`client-go` informers** — for when you want to understand what's
  happening below the manager. `k8s.io/client-go/tools/cache` is the
  underlying machinery.

- **The Kubernetes CSR API source** —
  https://github.com/kubernetes/kubernetes/tree/master/pkg/registry/certificates/certificates.
  Reading the apiserver's CSR REST handler will explain *why*
  `spec.username` is overwritten on create, what `/approval` does
  differently from `/status`, and so on. Worth doing once.

- **Go's standard `crypto/x509` package** — most of rules 4–6 and 9–12
  end up here. The package has decent godoc; PKCS#10 specifically lives
  on `CertificateRequest`.

---

This document is meant to be kept current with the code. If something here
becomes false because the code changes, fix the doc — that's part of the
diff.
