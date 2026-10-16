# zerotrust-gitops

**The declared state for the Zero-Trust Secure Supply Chain Platform.**
Everything that runs in the cluster, plus the terraform for the box it runs on,
plus the scripts that attack it.

ArgoCD watches this repository. After bootstrap there is exactly **one
`kubectl apply`** in the whole project: the root Application.

---

## Install order

Each script refuses to continue if its own preconditions are not met, so
running them in order is the whole procedure. `../BUILD-STEPS.md` has the
paste-ready version with the GitHub side included.

```bash
# From your workstation
./scripts/lab-up.sh                     # terraform, then waits for SSH

# On the box
./scripts/00-bootstrap-cluster.sh       # k3s + Istio (CNI, REGISTRY_ONLY)
./scripts/01-install-policy-engines.sh  # Kyverno + Falco
./scripts/02-install-argocd.sh          # ArgoCD

kubectl apply -f argocd/projects/zerotrust.yaml
kubectl apply -f argocd/root-app.yaml

./scripts/03-verify-enforcement.sh      # NOT optional
./scripts/attack-all.sh --audit-first
```

**Kyverno and Falco are installed by script, not by ArgoCD.** That is a design
decision, not a convenience:

- Kyverno is the admission controller that validates everything ArgoCD deploys.
  Deploying it *through* ArgoCD would make the thing being policed responsible
  for installing its own police — and a bad sync could remove the policy engine
  without being refused by it.
- Falco is the detection layer. Keeping it outside the GitOps path means a
  compromise of that path cannot remove the thing that would notice.

The AppProject reflects this: it does **not** permit `ClusterRole`,
`ClusterRoleBinding`, `CustomResourceDefinition` or webhook configurations.
A supply-chain project whose delivery path can register its own admission
webhook has a gap you could drive through.

## Sync waves

| Wave | Application | Path | Why here |
|---|---|---|---|
| 0 | `namespaces` | `namespaces/` | PSA labels must exist before anything is admitted into them |
| 1 | `kyverno-policies` | `policies/kyverno/` | Admission policy before any workload |
| 2 | `network-policies` | `network/` | Default-deny plus its exceptions, in one sync |
| 3 | `istio-security` | `istio/` | mTLS, authz and egress before the workloads they govern |
| 4 | `workloads` | `workloads/` | **Last.** The first pod ever admitted meets the complete set |

**Waves 2 is one Application and not five, deliberately.** NetworkPolicies are
additive, so there is no window in which default-deny is in force and the DNS
allowance is not — *provided they arrive in the same sync*. Split across waves,
`00-default-deny` would land first and the namespace would lose DNS until the
next wave completed. That gap is seconds long and enough to fail every
readiness probe in the namespace.

**A caveat measured on the previous project rather than assumed:** sync waves
order *creation*, not *success*. An Application whose manifests fail validation
sits in `Unknown`, which does not block later waves the way `Progressing` does.
So wave 4 can report Synced and Healthy while wave 1 is still failing — which
is exactly why `03-verify-enforcement.sh` tests behaviour rather than reading
`kubectl get` output.

## Layout

```
terraform/            one EC2 box, in its own VPC
argocd/               AppProject, root app, 5 Applications
namespaces/           wave 0 — PSA labels, Istio injection
policies/
  kyverno/            layer 3 — 5 ClusterPolicies + offline unit tests
  opa/                the same rules as Rego, for CI (shift left)
network/              layer 5 — default deny + 4 exception sets
istio/                layer 6 — mTLS, authz, egress allowlist, gateway
workloads/            the signed application, by digest
falco/                layer 7 — chart values + 4 custom rules
attacks/manifests/    standing fixtures for 4 of the 7 attacks
scripts/              bootstrap, verification, attacks, teardown
docs/                 ATTACK-RESULTS.md, threat model, runbook
```

## Scripts

| Script | Runs on | Purpose |
|---|---|---|
| `lab-up.sh` / `lab-down.sh` | workstation | Create and destroy the box. `lab-down` verifies against the AWS API |
| `00-bootstrap-cluster.sh` | box | k3s, Istio with CNI and `REGISTRY_ONLY`, istioctl, argocd, cosign |
| `01-install-policy-engines.sh` | box | Kyverno + Falco. `FALCO_UI=1` adds the event UI |
| `02-install-argocd.sh` | box | ArgoCD, `--enable-helm`, prints the bootstrap password |
| `03-verify-enforcement.sh` | box | **Six functional checks. Required.** |
| `04-verify-signature-identity.sh` | box | `cosign verify` with the right identity and a wrong one |
| `05-enable-commit-signing.sh` | workstation | Optional layer 2. GPG + AppProject `signatureKeys` |
| `policy-mode.sh` | box | Audit ↔ Enforce, and reports which you are in |
| `attack-01..07`, `attack-all.sh` | box | The seven attacks. `--audit-first` runs the set twice |
| `port-forwards.sh` | box | ArgoCD and the Falco UI |

## Versions

All pinned in `versions.env`, overridable from the environment:

```bash
KYVERNO_CHART_VERSION=3.8.2 ./scripts/01-install-policy-engines.sh
```

**Two pins are load-bearing** and the reasons are in that file. In short:
Kyverno 1.19 deprecates the `kyverno.io/v1 ClusterPolicy` API these policies
use, and the Falco chart silently ignores a key that moved between 4.x and 9.x
because it ships no values schema. Both were found by validating this
repository before the first cluster existed, and both are recorded in
`docs/ATTACK-RESULTS.md`.

## Testing, before anything is deployed

```bash
# Rendering
for d in namespaces policies/kyverno network istio workloads; do
  printf '%-20s %s\n' "$d" "$(kubectl kustomize "$d" | grep -c '^kind:')"
done
# expect 3, 5, 14, 12, 6

opa check --strict policies/opa && opa test policies/opa   # 15 tests
kyverno test policies/kyverno/tests                        # 24 tests
```

`.github/workflows/policy-test.yml` runs all of that on every pull request,
plus a grep that refuses any workload image referenced by tag.

**The policy tests matter more than they look.** The most common bug in a Rego
or Kyverno rule is that it silently matches **nothing**, in which case it
reports PASS forever. Both test suites include a case where the field under
test is *absent* rather than wrong, because that is the spelling that breaks a
naive rule — and it is also the common real-world case.

## Honest notes

- **Vault, secrets and observability are not here.** The previous project
  covered those; adding them would be padding. This one is about enforcement.
- **One namespace has PSA deliberately disabled.** `zt-psa-off` exists so the
  Kyverno privileged-container policy can be observed working alone. Without
  it, that policy is untestable and would pass whether or not it existed — PSA
  is a built-in admission plugin and always speaks first. A production cluster
  has no namespace like this.
- **`namespaceResourceBlacklist: []`** in the AppProject permits any namespaced
  resource within the three destination namespaces. A whitelist would be
  stricter and would need ten entries edited every time the architecture gains
  a resource type. The destinations already confine everything to namespaces
  containing nothing but this project.
- **The egress allowlist is hostname-level**, via SNI. Not path-level — that
  would mean terminating TLS to a third party inside the mesh.
