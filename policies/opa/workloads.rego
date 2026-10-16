# ===========================================================================
# OPA / Rego — the same rules as Kyverno, evaluated BEFORE the cluster.
#
# Run by conftest in CI (.github/workflows/policy-test.yml) against the
# rendered manifests in this repository.
#
# WHY BOTH THIS AND KYVERNO. They are not redundant, and the difference is
# WHEN they run:
#
#   conftest + OPA   on a pull request, against the YAML. No cluster, no
#                    credentials, about two seconds. Catches the mistake while
#                    the person who made it is still looking at it.
#
#   Kyverno          at admission, against the LIVE request, after every
#                    mutating webhook has run. Catches what the repository
#                    cannot see - an injected sidecar, a defaulted field, a
#                    resource created by something other than a commit.
#
# Each is blind to what the other sees. CI cannot evaluate a sidecar that does
# not exist until injection; admission control cannot review a pull request. A
# manifest that passes here and is refused at admission is the interesting
# case, and policies/kyverno/03-allowed-registries.yaml documents exactly
# that: the registry allowlist must permit docker.io/istio, which appears
# nowhere in this repository.
#
# Style note: `import rego.v1` is the forward-compatible syntax required by
# OPA 1.x and accepted by 0.59+. Without it, OPA 1.x rejects the older
# `deny[msg] { ... }` form outright.
# ===========================================================================
package main

import rego.v1

# ---------------------------------------------------------------------------
# Helpers, written to cope with every shape a pod spec arrives in - because a
# rule that silently inspects nothing is worse than no rule: it reports PASS.
#
# `object.get` with a default appears throughout for one specific reason.
# Indexing a missing key in Rego makes the expression UNDEFINED, and an
# undefined condition in a `deny` body means the rule does not fire. So the
# naive version of every rule below passes on exactly the manifests that omit
# the field it is checking.
# ---------------------------------------------------------------------------

pod_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}

all_containers contains c if {
	input.kind == "Pod"
	some c in input.spec.containers
}

all_containers contains c if {
	input.kind in pod_kinds
	some c in input.spec.template.spec.containers
}

all_containers contains c if {
	input.kind == "CronJob"
	some c in input.spec.jobTemplate.spec.template.spec.containers
}

all_containers contains c if {
	input.kind == "Pod"
	some c in object.get(input.spec, "initContainers", [])
}

all_containers contains c if {
	input.kind in pod_kinds
	some c in object.get(input.spec.template.spec, "initContainers", [])
}

pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if input.kind in pod_kinds

is_workload if input.kind == "Pod"

is_workload if input.kind in pod_kinds

name := object.get(input.metadata, "name", "<unnamed>")

# ---------------------------------------------------------------------------
# Images must be referenced by DIGEST.
#
# The rule Kyverno expresses as verifyDigest: true, checked here so it fails in
# a pull request rather than at admission. A tag is a mutable pointer: whoever
# can push to the registry can move it to different bytes after the scan, so a
# signature on a tag signs a promise somebody else may break.
# ---------------------------------------------------------------------------
deny contains msg if {
	some c in all_containers
	not contains(c.image, "@sha256:")
	msg := sprintf("%s/%s: container %q references %q by TAG. Pin images by digest (repo@sha256:...) - a tag can be moved after the image is scanned and signed.", [input.kind, name, c.name, c.image])
}

# ---------------------------------------------------------------------------
# No privileged containers.
# ---------------------------------------------------------------------------
deny contains msg if {
	some c in all_containers
	object.get(object.get(c, "securityContext", {}), "privileged", false) == true
	msg := sprintf("%s/%s: container %q is privileged. It would share the host kernel namespaces, which makes every other layer here irrelevant.", [input.kind, name, c.name])
}

# ---------------------------------------------------------------------------
# Read-only root filesystem - the control PSA `restricted` does NOT require,
# which is why it is worth checking at all.
#
# istio-proxy is excluded for the same reason as in the Kyverno policy: it is
# injected by a component this repository does not author. In CI it cannot
# appear at all, so the exclusion is here for symmetry, and so the two policy
# sets can be read side by side without wondering which rules differ.
# ---------------------------------------------------------------------------
deny contains msg if {
	some c in all_containers
	not c.name in {"istio-proxy", "istio-init"}
	object.get(object.get(c, "securityContext", {}), "readOnlyRootFilesystem", false) != true
	msg := sprintf("%s/%s: container %q does not set readOnlyRootFilesystem: true. A writable root filesystem is how a compromised container survives a restart.", [input.kind, name, c.name])
}

# ---------------------------------------------------------------------------
# Memory requests and limits, and a CPU request.
#
# No CPU LIMIT is demanded, matching policies/kyverno/04-require-resources.yaml:
# memory is incompressible so a ceiling bounds the damage, while a CPU limit
# causes throttling at p99 that gets misdiagnosed as an application bug.
# ---------------------------------------------------------------------------
deny contains msg if {
	some c in all_containers
	not c.name in {"istio-proxy", "istio-init"}
	some field in ["requests", "limits"]
	not object.get(object.get(c, "resources", {}), field, {}).memory
	msg := sprintf("%s/%s: container %q has no memory %s. An unbounded container can get the admission controller evicted, which disables every other policy.", [input.kind, name, c.name, field])
}

deny contains msg if {
	some c in all_containers
	not c.name in {"istio-proxy", "istio-init"}
	not object.get(object.get(c, "resources", {}), "requests", {}).cpu
	msg := sprintf("%s/%s: container %q has no CPU request. The scheduler and the QoS class both use it.", [input.kind, name, c.name])
}

# ---------------------------------------------------------------------------
# seccompProfile must be set AT POD LEVEL - not merely "set somewhere".
#
# PSA requires a profile on every container, and istio-proxy is added AFTER
# this manifest is submitted. A per-container profile therefore covers the
# application and not the sidecar, and PSA rejects the whole pod naming a
# container that appears nowhere in the repository. A pod-level profile is
# inherited by containers injected later, and is the only placement that
# composes with sidecar injection.
#
# This rule is the single best argument for having CI policy at all: it
# encodes a fact about how two systems interact that no amount of reading
# either manifest on its own would reveal.
# ---------------------------------------------------------------------------
deny contains msg if {
	is_workload
	object.get(object.get(pod_spec, "securityContext", {}), "seccompProfile", {}) == {}
	msg := sprintf("%s/%s: no pod-level securityContext.seccompProfile. Set it on the POD, not per container - the injected istio-proxy will not have one otherwise, and PSA restricted then rejects the whole pod.", [input.kind, name])
}

# ---------------------------------------------------------------------------
# Namespaces must declare their Pod Security Admission level.
#
# An unlabelled namespace inherits the cluster default, which on k3s is
# `privileged`. Layer 4 is made entirely of these labels, so a namespace added
# without them is a hole that nothing reports.
# ---------------------------------------------------------------------------
deny contains msg if {
	input.kind == "Namespace"
	not object.get(input.metadata, "labels", {})["pod-security.kubernetes.io/enforce"]
	msg := sprintf("Namespace/%s: no pod-security.kubernetes.io/enforce label. It inherits the cluster default (privileged on k3s) and will admit anything, silently.", [input.metadata.name])
}

# ---------------------------------------------------------------------------
# WARN, rather than deny, on the deliberately weakened test namespace.
#
# zt-psa-off exists so the Kyverno privileged-container policy can be observed
# working on its own - see namespaces/ns-zt-psa-off.yaml. It must not fail the
# build, and it must not pass unremarked either. A warning is what makes it a
# documented exception rather than an oversight nobody noticed.
# ---------------------------------------------------------------------------
warn contains msg if {
	input.kind == "Namespace"
	object.get(input.metadata, "labels", {})["pod-security.kubernetes.io/enforce"] == "privileged"
	msg := sprintf("Namespace/%s runs at PSA `privileged` - no pod security enforcement. Intentional, for the Kyverno isolation test. No real workload belongs here.", [input.metadata.name])
}
