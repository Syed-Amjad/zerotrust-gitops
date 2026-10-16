# Screenshots

**Nine worth having**, in the order they should appear in a write-up. The
images themselves are not committed — put them on the website and keep this
list as the shot plan.

**Lead with number 4.** A rejection message naming the policy, the rule and the
reason is the single most persuasive image in the set: it is the moment the
platform refuses something, in the cluster's own words.

| # | Shot | What must be legible | Why this one |
|---|---|---|---|
| 1 | `build-sign` workflow, all jobs green | The five step names: build, SBOM, scan, sign, verify | Shows the ORDER. Signing after scanning is what makes the signature mean "passed the gate" |
| 2 | `cosign verify` output | `Subject:` showing the workflow path, and `logIndex` | The identity binding in one frame. The log index is the transparency-log proof |
| 3 | `04-verify-signature-identity.sh`, both halves | Correct identity PASS, wrong identity refused | The second half is the real evidence. Without it a wildcard subject would look identical |
| 4 | **Admission rejection, attack 1** | The policy name and `no matching signatures` | **Lead with this.** The platform refusing an unsigned image |
| 5 | Attack 2, both namespaces side by side | A `PodSecurity` message *and* a Kyverno message | Two layers, two mechanisms. Defence in depth rather than one control with a spare written next to it |
| 6 | `03-verify-enforcement.sh`, all six passing | The six check names and PASS | The project's actual thesis: the controls were tested, not assumed |
| 7 | ArgoCD UI, five Applications Synced + Healthy | Wave numbers 0 to 4 | Everything from git, in order, workloads last |
| 8 | Attack 4, all four results | 403, connection refused, 200, 403 | Identity versus label, and path granularity, in one frame |
| 9 | Falco alert from attack 7 | `k8s.ns.name=zt-prod` and the rule name | The context is the point. An alert saying `<NA>` would mean the scoped rules never fired |

## Also worth capturing

| Shot | Why |
|---|---|
| `policy-mode.sh` in Audit, then Enforce | The same attack admitted, then refused. Shows the policy is doing the blocking |
| `kubectl get polr -A` with failures | Audit mode working: violations recorded, nothing blocked |
| `attack-05` full output | The declared host reachable AND the undeclared ones refused. One without the other proves nothing |
| `kyverno test` — 24 passed | Policies are tested code, not hopeful YAML |
| `opa test` — 15 passed | The same point, shifted left |
| `lab-down.sh` — "Clean. Nothing is billing." | Verified against the AWS API, not terraform state |

## Before you screenshot anything

**Blur or crop:**

- the ArgoCD bootstrap password, printed by `02-install-argocd.sh`
- the public IP of the box, in SSH prompts and terraform output
- the AWS account id, in `sts get-caller-identity` output
- your home IP, in the `allowed_ssh_cidr` output
- any `ghp_` or `github_pat_` string, anywhere

Nothing in this project needs a secret visible to make its point. A rejection
message is more convincing than a password.

**Prefer a terminal to a UI.** The GitOps platform's write-up found that
terminal output read as evidence and dashboards read as decoration. The
exceptions here are shots 7 and 9, where the relationship between objects is
the thing being shown.

**Capture the whole command, not just the output.** A rejection with the
`kubectl apply` that caused it directly above is self-explanatory. The same
message alone needs a caption.
