# Runbook — rolling out an admission policy without causing an outage

**Written to be followed by someone else**, including someone who did not write
the policy and is doing this at 4pm on a Friday because a ticket said to.

The procedure is the same whether you are adding a policy, tightening one, or
switching the whole set from Audit to Enforce.

---

## Why this needs a runbook

An admission policy is the only kind of change that can **retroactively break
things that are already working**. It does not affect running pods — it affects
the *next* time any of them is created. So the blast radius is not "the thing I
changed"; it is "everything that restarts for any reason after I changed it".

A node drain, an eviction, an OOM kill, a `rollout restart` someone else runs —
each of those becomes an outage, hours after the change, and the symptom is a
pod that will not start rather than a policy that was tightened. Whoever is
paged will not connect the two.

---

## Before you start

```bash
# 1. Where are we now?
./scripts/policy-mode.sh

# 2. What is currently failing?
kubectl get polr -A -o wide
```

Write down the current state. If a policy is already in Enforce and you are
adding another, you are in a different situation from a first rollout.

---

## Step 1 — test it offline, with no cluster

```bash
# The Rego equivalent, and its own unit tests
opa check --strict policies/opa
opa test policies/opa

# The Kyverno policies against fixtures
kyverno test policies/kyverno/tests
```

**Add a fixture for the new rule, in both directions.** One resource that must
be refused, and one that must pass. The second is not a formality: a rule that
denies everything is as useless as one that denies nothing, and much easier to
ship by accident — the failing CI run looks like the policy working.

**And add a fixture where the field is ABSENT**, not merely wrong. That is the
spelling that breaks a naive rule, because in both Rego and Kyverno a missing
key makes the condition undefined, and an undefined condition **does not
deny**. It is also the common real-world case: people omit fields far more
often than they set them to the wrong value.

## Step 2 — apply it in Audit

Every policy in `policies/kyverno/` ships with
`validationFailureAction: Audit`. Keep it that way for the first sync.

```bash
git add policies/ && git commit -m "Add <policy>" && git push
kubectl -n argocd get app kyverno-policies -w      # Ctrl-C when Synced
```

## Step 3 — read the reports, and understand every row

```bash
kubectl get polr -A -o json | jq -r '
  .items[].results[]? | select(.result=="fail")
  | "\(.policy)/\(.rule)  →  \(.resources[0].namespace)/\(.resources[0].name)"
' | sort | uniq -c | sort -rn
```

**Do not proceed until you can explain every line.** Three outcomes:

| What you see | What it means | Do |
|---|---|---|
| Only the deliberate fixtures | The policy is correct and nothing real violates it | Go to step 4 |
| A real workload fails | Either the workload is wrong, or the policy is | **Fix the workload first**, in git |
| A workload you did not expect to be evaluated | The match block is wider than you intended | Fix the policy |

**Background scanning is why this step works at all.** Policies with
`background: true` re-evaluate existing resources on a timer and report on
them, so you see what *would* have been refused. Note the exception:
`verifyImages` policies must set `background: false`, so the signature policy
reports only on admissions that happen while it is in Audit — it will not tell
you about pods already running.

That is a real gap in this procedure. For the signature policy, the equivalent
check is to verify by hand:

```bash
./scripts/04-verify-signature-identity.sh
```

## Step 4 — switch to Enforce

```bash
./scripts/policy-mode.sh enforce
```

It prints every currently-failing resource first and then switches. Those
resources are now unable to restart.

```bash
./scripts/policy-mode.sh        # confirm
```

## Step 5 — force the question, deliberately

**Enforce takes effect at the next admission, not now.** Running pods are never
re-evaluated. So at this point you have a cluster that reports compliant and
contains pods that have never been through the new policy.

You find out either when you choose to, or at 3am during a node failure. Choose
to:

```bash
kubectl -n zt-prod rollout restart deploy/api deploy/web
kubectl -n zt-prod rollout status deploy/api --timeout=180s
kubectl -n zt-prod rollout status deploy/web --timeout=180s
```

If a rollout hangs, the new policy is refusing the pod. The reason is in the
ReplicaSet, not the Deployment:

```bash
kubectl -n zt-prod describe rs -l app=api | tail -25
```

## Step 6 — prove it refuses what it should

```bash
./scripts/attack-all.sh
```

A policy in Enforce that has never refused anything is indistinguishable from
one that is not working.

---

## Rollback

```bash
./scripts/policy-mode.sh audit
```

Instant, and it does not require a sync. Violations go back to being recorded
rather than blocked.

To remove the policy entirely, delete it from `policies/kyverno/` and from
`kustomization.yaml`, then commit — `prune: true` is set on the Application, so
ArgoCD removes it from the cluster.

**If you roll back, write down why.** An "Audit for now" that nobody revisits
is the normal end state of a policy project, and the file it belongs in is
`docs/ATTACK-RESULTS.md` rather than someone's memory.

---

## Emergencies

### A policy is blocking a deployment you need right now

```bash
./scripts/policy-mode.sh audit      # everything, ~1 second
```

Blunt and fast. Prefer it to editing one policy under pressure — a hand-edited
policy is drift, and `selfHeal` will revert it in seconds anyway, which will be
confusing on top of an incident.

For a longer-lived, auditable exception, Kyverno has `PolicyException`. There
is none in this repository on purpose: an exception mechanism available during
an incident becomes the permanent answer.

### Kyverno is down and nothing can be scheduled

Expected. Every policy here sets `failurePolicy: Fail`, so an unreachable
webhook denies the request.

```bash
kubectl -n kyverno get pods
kubectl -n kyverno logs -l app.kubernetes.io/component=admission-controller --tail=100
```

The trade-off is deliberate and stated in the policies: `Ignore` would mean an
attacker who can crash the admission controller has also disabled every policy
behind it. **Fix Kyverno; do not switch to `Ignore` to get past an incident**,
because that change will outlive the incident.

Genuine last resort, if the cluster must take workloads and Kyverno cannot be
recovered:

```bash
kubectl delete validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg
```

That disables layer 3 entirely. Layers 4, 5, 6 and 7 still apply. Write it down
and restore the webhook — `helm upgrade` recreates it.

### Admission requests are timing out

The signature policy makes network calls at admission time to ghcr.io, Fulcio
and Rekor. `webhookTimeoutSeconds` is already 30, the maximum Kubernetes
allows, so if that is not enough the problem is the network path rather than
the setting.

```bash
kubectl -n kyverno logs -l app.kubernetes.io/component=admission-controller \
  --tail=100 | grep -i 'rekor\|fulcio\|timeout'
```

Check that the `kyverno` namespace is **not** labelled for Istio injection. An
injected Kyverno under `REGISTRY_ONLY` cannot reach Sigstore, and the symptom
is a webhook timeout that looks like Kyverno being unhealthy.
