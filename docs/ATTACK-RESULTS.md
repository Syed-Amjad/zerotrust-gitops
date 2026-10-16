# Attack Results

**This file is the point of the project.** The manifests describe intent; these
are the observations. On the GitOps platform the equivalent file
(`DEMO-RESULTS.md`) turned out to be the single most persuasive artifact in the
repository, and this one works the same way.

Fill in a row every time you run an attack, **from
`docs/attack-run-<timestamp>.log` while it is in front of you.** A result typed
from memory an hour later is a description rather than an observation.

**Copy the actual error message in.** The message is the evidence, because it
names *which layer spoke*. "Rejected" on its own could have come from any of
four places — and in attack 2 the whole finding is which one answered.

**Do not tidy out the failures.** A table containing only the expected outcomes
tells a reader you deleted the interesting rows.

---

## Environment

| | |
|---|---|
| Node | `t3.large` (8 GB), Ubuntu 24.04, single-node k3s |
| Mesh | Istio `<version>`, CNI enabled, `outboundTrafficPolicy: REGISTRY_ONLY` |
| Admission | Kyverno `<version>`, 5 ClusterPolicies |
| Runtime | Falco `<version>`, `modern_ebpf` driver |
| GitOps | ArgoCD `<version>`, 5 Applications, waves 0-4 |
| Date | `<date>` |
| Memory in use | `<free -h>` — expected around 5.1 GB |

---

## Precondition — `03-verify-enforcement.sh`

**Record this before the attacks.** If any check failed, every attack below it
passes for the wrong reason, and the transcript is worse than no transcript
because it looks like evidence.

| # | Check | Result | Notes |
|---|---|---|---|
| 1 | Istio traffic redirection (plaintext from outside the mesh refused) | ⬜ | |
| 2 | NetworkPolicy enforced (unlisted workload blocked below HTTP) | ⬜ | |
| 3 | PSA enforcing `restricted` | ⬜ | |
| 4 | Kyverno webhook registered, 5 policies loaded | ⬜ | |
| 5 | `REGISTRY_ONLY` and a ServiceEntry present | ⬜ | |
| 6 | Falco driver loaded, events carry `k8s.ns.name` | ⬜ | |

---

## The seven attacks

| # | Attack | Layer | Expected | Result | Date |
|---|---|---|---|---|---|
| 1 | Unsigned image deployed | 3 — Kyverno `verifyImages` | Rejected at admission | ⬜ | |
| 2 | Privileged container | 4 — PSA, **and** 3 — Kyverno | Rejected in both namespaces, by a different layer in each | ⬜ | |
| 3 | Image from an undeclared registry | 3 — Kyverno allowlist | Rejected at admission | ⬜ | |
| 4 | Service call from an unauthorised workload | 6 — Istio AuthorizationPolicy | HTTP 403 with a sidecar; refused without one | ⬜ | |
| 5 | Exfiltration to an undeclared host | 6 — `REGISTRY_ONLY`, over 5 | Declared host reachable, everything else refused | ⬜ | |
| 6 | Manual edit of a live resource | 2 — ArgoCD `selfHeal` | Reverted to the git-declared state | ⬜ | |
| 7 | Shell spawned in a container | 7 — Falco | **Succeeds**, and is detected with full context | ⬜ | |

### Audit versus Enforce

`./scripts/attack-all.sh --audit-first` runs the set twice. **Both columns
matter** — the Audit pass is what shows the policies are doing the blocking in
the second pass, rather than something else being responsible.

| # | In Audit | In Enforce |
|---|---|---|
| 1 | ⬜ admitted, violation reported | ⬜ rejected |
| 2 | ⬜ | ⬜ |
| 3 | ⬜ | ⬜ |

Attacks 4-7 do not depend on Kyverno's mode: 4 and 5 are enforced by Istio, 6
by ArgoCD, 7 by Falco. Note any difference anyway — a change there would be a
finding.

---

## Attack 1 — unsigned image

**Control sample:** `ghcr.io/syed-amjad/zt-unsigned-control`, published by the
CI workflow on every run with no signature, by a job that has no
`id-token: write` permission and therefore cannot sign even by accident.

Same registry, same owner, same Dockerfile, same pipeline, matched by the same
Kyverno glob. **The only difference is the signature** — which is what makes
the result mean anything. `nginx:latest` would have been refused by the
*registry* allowlist first, and the signature policy never consulted.

```
<paste the admission rejection here>
```

| Observation | |
|---|---|
| Rejected? | ⬜ |
| Policy named in the message | |
| Time to rejection | |
| Deployment path: accepted, pods refused in ReplicaSet events? | ⬜ |

**On that message.** `no matching signatures` is also what you get when a
signature exists but its certificate identity does not match the pinned
subject. The two are not distinguished, so when a *legitimate* image is
rejected, check the `subject:` in policy 01 before concluding the signing step
failed.

---

## Attack 2 — privileged container, twice

The attack that tests the test. Submitting a privileged pod to `zt-prod` proves
only that *something* refused it — and it is always PSA, because built-in
admission plugins run before validating webhooks. The Kyverno policy would pass
that test whether or not it existed.

**`zt-prod` (PSA at `restricted`):**

```
<paste - expect a PodSecurity message, with no mention of Kyverno>
```

**`zt-psa-off` (PSA disabled, Kyverno alone):**

```
<paste - expect a Kyverno message naming disallow-privileged>
```

| Observation | |
|---|---|
| Which layer spoke in `zt-prod`? | |
| Which layer spoke in `zt-psa-off`? | |
| Two distinct messages? | ⬜ |

Two rejections, two mechanisms, two messages is the evidence that two layers
exist. One rejection twice is the evidence that one does.

---

## Attack 3 — undeclared registry

```
<paste>
```

| Observation | |
|---|---|
| Rejected? | ⬜ |
| Path named in the message | `/spec/containers/_/image` |
| Did `api` keep running with its sidecar? | ⬜ |

That last row is the negative half and it is not optional. An allowlist that
rejects everything is not a working allowlist, and the most likely thing for it
to break is the **injected sidecar** — which surfaces as the whole mesh failing
rather than as a policy problem. If a legitimate pod is ever rejected by this
policy, the path will read `/spec/containers/1/image`; container 1 is
`istio-proxy`, added 20 milliseconds earlier by another webhook, and searching
the repository for that image finds nothing.

---

## Attack 4 — unauthorised service call

The imposter pod is labelled `app: web` **on purpose**, so the NetworkPolicy
permits it. It runs as the `default` ServiceAccount, so the mesh does not.

| Variant | Expected | Observed |
|---|---|---|
| A — with sidecar (valid cert, wrong identity) | HTTP 403, RBAC denied | |
| B — no sidecar (`inject: false`, plaintext) | No HTTP response; connection refused | |
| Positive control — real `web` to `/data` | HTTP 200 | |
| Granularity — real `web` to `/whoami` | 403, not in the allowed paths | |

```
<paste all four>
```

**Why A and B must be recorded separately.** In A the mesh *authenticated* the
caller and then declined to *authorise* it — two distinct steps, and the
existence of an HTTP response proves mTLS succeeded. In B the TLS handshake
failed and there was never a request to authorise.

Recording them as one row loses the useful part: **a control set that only ever
sees B is a control set whose authorization rules have never been exercised.**

The `/data` versus `/whoami` pair is the other half: a path-level distinction,
from the same pod over the same connection, by the same policy. NetworkPolicy
structurally cannot express that — at L3/L4 a connection is permitted or not,
and every URL on the far side rides the same one.

---

## Attack 5 — egress exfiltration

Driven through `web`'s `/fetch` endpoint, which is a deliberate SSRF built into
the application. Not `kubectl exec curl`: an exec'd shell is already inside the
pod's network namespace, so it would test the control against a threat nobody
is modelling. The threat here is a request arriving from outside and the
application honouring it.

| Target | Expected | Observed |
|---|---|---|
| `https://api.github.com/zen` (declared) | **200 — reachable** | |
| `https://example.com/` | Blocked by the sidecar | |
| `https://pastebin.com/raw/...` | Blocked by the sidecar | |
| `http://169.254.169.254/latest/meta-data/` | Blocked | |
| `https://169.254.169.254/latest/meta-data/` | Blocked | |

```
<paste>
```

The first row matters as much as the rest. **An egress policy that refuses
everything is indistinguishable from a broken network**, and would make every
other row meaningless.

The metadata endpoint fails for **three independent reasons**, all real:

1. Istio `REGISTRY_ONLY` — not a declared destination
2. NetworkPolicy — `169.254.0.0/16` is in the `except` list, and plaintext port
   80 is not permitted outbound at all, so the `http://` variant is refused for
   a second, different reason
3. The instance — IMDSv2 required with `http_put_response_hop_limit = 1`, so a
   response cannot leave the pod network namespace; and **no IAM role is
   attached**, so there would be nothing to read

Removing them one at a time is how you find out which are load-bearing. Worth
doing; deliberately *not* what the script does, because it would leave the
cluster weakened and a later attack would then pass through the gap silently.

---

## Attack 6 — manual edit, and the measured revert

| Observation | |
|---|---|
| `selfHeal` confirmed on? | ⬜ |
| Declared replicas | |
| Tampered to | |
| **Measured seconds to revert** | |

```
<paste the countdown>
```

**Record the seconds, not "fast".** ArgoCD's default reconcile interval is 180s
and `selfHeal` reacts to the cluster event much sooner, so the number tells you
*which path* corrected it — and a slow revert is a real window an attacker
could work inside.

**The limitation.** `selfHeal` reverts resources ArgoCD *manages*. A pod created
by hand in `zt-prod` is not drift; it is simply unmanaged, and reconciliation
has no opinion about it. `orphanedResources.warn` is on, and a warning in a UI
is weaker than a rejection. The layer that actually stops a hand-created pod is
admission control, not GitOps.

---

## Attack 7 — shell in a container

**This one succeeds.** Layers 1-6 are preventive and have nothing to say about
a process already running inside a container that was correctly signed,
admitted and isolated.

| Observation | |
|---|---|
| Shell ran? | ⬜ **expected yes** |
| Falco alerted? | ⬜ |
| `k8s.ns.name` populated, not `<NA>`? | ⬜ |
| Alerts from the **custom** rules, not just the defaults? | ⬜ |
| Rules fired (expect 3) | |
| Alert latency | |

```
<paste the alerts>
```

**The real test is not "did an alert arrive".** An alert with
`k8s.ns.name=<NA>` means Falco detected the syscall correctly and has no idea
which pod it happened in — in which case every rule in `falco/custom-rules.yaml`
is scoped to a namespace it cannot see, matches nothing, and never fires. What
you would be reading is the *default* ruleset, which looks like success.

One exec session trips three rules: shell spawned, credential file read, and a
write attempted into `/usr/bin` — which **failed with EROFS**, because layer 3's
read-only root filesystem blocked it.

### A finding worth more than the rules

That third rule had to be written by hand. Falco's built-in `open_write` macro
includes `fd.num >= 0`, meaning *the open succeeded*; a failed open returns -1
and is excluded. So **every default rule built on `open_write` is structurally
blind to an attempt that a read-only filesystem blocked.**

Hardening layer 3 made layer 7 blind to the clearest signal of
post-exploitation activity — an attacker probing for somewhere to persist.
Nothing warns you about that interaction. It is only visible by attacking your
own cluster and noticing an alert that did not arrive.

---

## Defects found

Record everything, including defects in this repository and mistakes made while
running it. On the GitOps platform seventeen surfaced this way and became the
most interesting section of the whole write-up.

**Two were found before the first cluster existed**, by validating the
repository rather than by running it.

| # | Defect | How it presented | Status |
|---|---|---|---|
| 1 | **Falco values written against the chart 4.x schema.** `collectors.containerd.socket` does not exist in chart 9.x; the setting is now a *list* at `collectors.containerEngine.engines.cri.sockets`. | The chart ships **no `values.schema.json`**, so Helm accepted the unknown key silently — no warning, exit 0. The install would have succeeded, Falco would have run, and the setting would have had no effect. Found by rendering the chart and reading the output, not by reading either file: both looked correct. | **Fixed.** Chart 9.x's default list already contains the k3s path, so the symptom would not have appeared on this version — on any other it would have been `k8s.ns.name=<NA>` on every event and five silently inert rules. |
| 2 | **`kyverno.io/v1 ClusterPolicy` is deprecated** as of Kyverno 1.19, which directs users to `ImageValidatingPolicy` instead. | A warning on every `kyverno test` run. The policies were verified working on 1.19.1 regardless: 24/24 unit tests passed, and policy 01 reached ghcr.io and correctly refused an unsigned digest. | **Pinned, not worked around.** An unpinned install would eventually stop enforcing on a cluster whose manifests had not changed — and `kubectl get clusterpolicy` would still list all five. The migration path is named in `versions.env`. |
| 3 | | | |
| 4 | | | |
| 5 | | | |

### Expected traps, and whether they were hit

Each of these was predicted in the repository before the first run. Record
whether it actually happened — **a prediction that did not come true is as
informative as one that did**, and silently dropping the ones that missed would
make the list look better than the engineering was.

| Trap | Predicted in | Hit? |
|---|---|---|
| Istio CNI paths wrong → silent non-enforcement | `scripts/00-bootstrap-cluster.sh` | ⬜ |
| PSA rejects a pod naming `istio-init` capabilities | `scripts/00-bootstrap-cluster.sh` | ⬜ |
| PSA rejects a pod naming `istio-proxy` seccomp | `workloads/api.yaml` | ⬜ |
| Registry allowlist rejects the injected sidecar | `policies/kyverno/03-allowed-registries.yaml` | ⬜ |
| Default-deny breaks DNS | `network/01-allow-dns.yaml` | ⬜ |
| Default-deny severs the sidecar from istiod | `network/03-allow-istio-control-plane.yaml` | ⬜ |
| Kyverno webhook times out reaching Sigstore | `policies/kyverno/01-verify-image-signature.yaml` | ⬜ |
| Sync waves do not hold under validation failure | `workloads/kustomization.yaml` | ⬜ |
| Trivy gate fails on unfixable base-image CVEs | `build-sign.yml` | ⬜ |
| GHCR package private → Kyverno cannot fetch the signature | `supply-chain-app/README.md` | ⬜ |

---

## Timings worth recording

Measurements, not configurations. "Configured to revert" proves nothing;
"reverted in 4 seconds" proves reconciliation is running.

| Measurement | Observed |
|---|---|
| Fresh box to `kubectl get nodes` ready | |
| Bootstrap script total (k3s + Istio) | |
| All 5 Applications Synced + Healthy | |
| Memory in use with everything running | |
| Admission rejection latency, signature policy | |
| Admission rejection latency, a non-network policy | |
| Drift revert (attack 6) | |
| Falco alert latency (attack 7) | |
| Full `attack-all.sh --audit-first` run | |
| Total AWS cost for the session | |

The two admission latencies are worth comparing. The signature policy makes
network calls to ghcr.io, Fulcio and Rekor at admission time; the others are
local computation. The difference is the price of verification, and it is why
`webhookTimeoutSeconds` is set to 30 — the maximum Kubernetes permits.

---

## Limitations

Lab-grade, and stated rather than implied away. On the previous project,
statements exactly like these did more for credibility than any of the green
output.

- **Single-node k3s.** No multi-node NetworkPolicy testing on a real CNI, no
  etcd encryption at rest, no managed control plane.
- **Five admission policies in three namespaces.** A working baseline, not a
  control catalogue.
- **The egress allowlist filters on hostname (SNI), not path.** Path-level
  control over external HTTPS would mean terminating TLS to a third party
  inside the mesh — a man-in-the-middle of your own traffic, with its own
  certificate distribution problem.
- **Falco alerts into a pod log and falcosidekick.** An alert nobody is paged
  for is the same class of problem as a policy left in Audit.
- **GitHub Actions pinned to mutable tags**, not commit SHAs. In a supply-chain
  project the honest statement is that SHAs are the answer; the reason and the
  fix are both recorded in the workflow.
- **Signed commits implemented, off by default.** Enabling them breaks the
  automated digest bump because CI pushes with no key — which is the control
  working rather than a flaw.
- **One deliberately weakened namespace.** `zt-psa-off` exists so attack 2 can
  isolate the Kyverno layer. A production cluster has no namespace like this.
- **No SLSA provenance attestation.** `provenance: false` is set on the build
  deliberately: buildx would otherwise produce an OCI image *index*, cosign
  would sign the index digest, and the signature would verify by hand while
  being refused at admission. Adding provenance properly is the obvious next
  step, and it needs the policy to understand an index.
