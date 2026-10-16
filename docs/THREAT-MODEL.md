# Threat model

**What this platform defends against, what it does not, and which layer is
doing the work in each case.**

A control set without a threat model is a list of features. The useful question
is never "is this secure" but "secure against whom, doing what" — and the
honest answer always includes a column of things you have not addressed.

---

## Assets

| Asset | Why it matters |
|---|---|
| The cluster's workloads | What an attacker wants to run code in |
| The container registry (`ghcr.io/syed-amjad/*`) | Push access here is push access to production, absent verification |
| The GitOps repository | Write access here is write access to declared cluster state |
| The CI signing identity | Whoever has it can produce artifacts the cluster will accept |
| Node credentials (IMDS) | A path from a pod to the cloud account |

---

## Adversaries, in order of how likely they are

### 1. A careless or hurried insider — the most probable, by far

Not malicious. Someone copies a manifest from a blog post, pulls an image from
Docker Hub to debug something, scales a Deployment during an incident and never
reverts it, or removes a `securityContext` field to make a pod start.

| Attempt | Stopped by | Attack |
|---|---|---|
| Public image from an undeclared registry | Layer 3, registry allowlist | 3 |
| Privileged container | Layer 4, then layer 3 | 2 |
| Writable root filesystem | Layer 3 — PSA does **not** cover this | — |
| Missing resource limits | Layer 3 | — |
| Manual edit of a live resource | Layer 2, reconciliation | 6 |
| Image referenced by tag | Layer 3, `verifyDigest: true` | 1 |

This is where most of the value of the whole platform sits, and it is the least
glamorous row in the table.

### 2. A compromised dependency — the most probable *attack*

The realistic supply-chain attack is not someone breaking into your registry.
It is a package in `requirements.txt` gaining a malicious maintainer, or a
transitive dependency being typosquatted.

| Stage | What happens | Layer |
|---|---|---|
| Malicious package merged | Trivy scans the built image; fails on fixable HIGH/CRITICAL | 1 |
| Unknown, so the scan is clean | **Nothing stops it.** It is signed, admitted and running | — |
| Code executes in the container | Falco sees a shell, a credential read, a write attempt | 7 |
| It tries to persist a binary | Read-only root filesystem refuses | 3 |
| It tries to reach a C2 host | `REGISTRY_ONLY` refuses an undeclared destination | 6 |
| It tries to read node credentials | Three independent controls refuse | 5, 6, instance |
| It tries to reach another service | Deny-all plus one identity-scoped rule | 6 |

**Note the empty row.** A zero-day in a dependency defeats layer 1 completely,
and the platform's answer is not prevention — it is that the compromised
workload can reach almost nothing, and that what it does try is recorded. That
is what "assume breach" means when it is implemented rather than said.

### 3. Stolen registry credentials

A GHCR token leaks — in a log, a screenshot, a committed `.env`.

**The attacker can push any image they like under our name. The cluster will
never run it.** No Fulcio certificate naming our workflow exists for that
digest, so layer 3 refuses it, and `scripts/04-verify-signature-identity.sh`
tests exactly this by verifying against a *wrong but plausible* identity and
requiring the attempt to fail.

This is the claim the project is built around, and it is also the narrowest.
It holds only because:

- the signature identity is pinned to **one repository, one workflow file, one
  branch** — loosen any part and the claim weakens correspondingly
- images are referenced by **digest**, so a moved tag changes nothing
- Rekor is **append-only**, so a backdated signature is detectable

### 4. A compromised CI pipeline

Someone obtains write access to `supply-chain-app` and can modify the workflow.

**They can sign images the cluster accepts.** Layer 1 is defeated by
definition — the signing identity *is* that workflow.

What remains: the image still has to pass layers 3 to 6. It cannot be
privileged, cannot come from elsewhere, cannot write to its own filesystem,
cannot reach undeclared destinations, and cannot call `api` unless it holds the
`web` ServiceAccount. And **CI has no kubeconfig**, so the pipeline cannot
change any of those rules — it can only move a digest in the GitOps repository.
That separation is the reason for two repositories.

Optional layer 2 (signed commits) narrows it further: a commit CI pushes is
unsigned, so with `signatureKeys` set, ArgoCD refuses to sync it at all.

### 5. An attacker with cluster credentials

Out of scope, and worth saying plainly rather than leaving ambiguous.

Someone with `cluster-admin` can delete the Kyverno webhook, relabel the
namespaces and remove the AuthorizationPolicy. Nothing in this project prevents
that, because nothing can: the controls are objects in the cluster they are
protecting.

What they would still face is **detection** — layer 7 is a DaemonSet outside
the GitOps path, so it is not removable by a commit — and reconciliation, which
reverts declared state. Both are detective rather than preventive. The real
mitigations (strong RBAC, short-lived credentials, audit log shipped off the
cluster) are a different project.

---

## What is explicitly NOT defended

| Gap | Why not, here |
|---|---|
| **etcd at rest** | Single-node k3s. Needs a managed control plane or manual encryption-at-rest configuration |
| **Node compromise** | An attacker with root on the node is past every control in this project |
| **Cluster-admin abuse** | See adversary 5. Needs RBAC design and an off-cluster audit log |
| **A zero-day in a dependency** | Layer 1 cannot see it. Layers 3, 6 and 7 contain and record it |
| **Istio control-plane compromise** | istiod issues every identity in the mesh. Compromise it and layer 6 is yours |
| **Kyverno compromise** | Same shape. `failurePolicy: Fail` means a *broken* Kyverno blocks deployments; a *subverted* one approves them |
| **Path-level egress filtering** | Would need TLS termination to third parties inside the mesh |
| **Secrets management** | No secrets in this build. The previous project covered Vault and External Secrets |
| **Image provenance (SLSA)** | `provenance: false` is set to avoid an OCI-index signing mismatch. The obvious next addition |
| **Alert delivery** | Falco alerts reach a pod log and falcosidekick, not a person |

---

## The honest summary

This platform raises the cost of three specific things:

1. **Running an artifact nobody built here** — from trivial to requiring the
   build workflow's identity
2. **Moving laterally after a compromise** — from "the network is flat" to
   "one path, one identity, one method"
3. **Acting without leaving a trace** — from nothing, to syscall-level records
   of the actions that matter

It does not make the cluster unbreakable, and the attack table does not claim
to. **Attack 7 succeeds**, and it is in the results precisely because a results
table where everything is blocked is a results table nobody should believe.

The thing most worth taking from this project is not any individual control. It
is that **four of the seven layers can fail with no error anywhere** — and that
the only way to know is to attack your own cluster and check that what should
have failed did.
