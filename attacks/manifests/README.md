# Attack manifests

**Most of the attacks build their manifests inline**, in the scripts in
`../../scripts/`. That is deliberate rather than untidy.

An attack fixture has to reference the *current* signed digest — read out of
`workloads/api.yaml`, which CI rewrites on every green build — and it has to
satisfy every control except the one under test. A pod that fails three
policies produces three rejections and proves nothing about any of them. Both
of those are easier to get right, and to read, as a heredoc next to the
assertion than as a file that has to be kept in sync by hand.

The files here are the ones worth having as standing artifacts: they are
referenced by `docs/THREAT-MODEL.md`, and they are what you hand someone who
asks "show me the thing that gets rejected" without wanting to read a script.

| File | Attack | Expected |
|---|---|---|
| `01-unsigned-image.yaml` | 1 | Rejected: no matching signature for the pinned workflow identity |
| `02-privileged.yaml` | 2 | Rejected by PSA in `zt-prod`; by Kyverno in `zt-psa-off` |
| `03-untrusted-registry.yaml` | 3 | Rejected: `docker.io/library` is not on the allowlist |
| `04-imposter-identity.yaml` | 4 | Admitted, then refused by `api`'s sidecar with HTTP 403 |

```bash
# All four, against the live policy set:
kubectl apply -f attacks/manifests/ --dry-run=server
```

`--dry-run=server` runs the full admission chain — mutating webhooks, PSA,
Kyverno — and creates nothing. It is the right way to read the rejection
messages without leaving fixtures behind in the cluster.

**`--dry-run=client` would report success on all four.** It never contacts the
API server, so no admission controller is consulted. A test that passes
because nothing evaluated it is the failure mode this whole project is about.
