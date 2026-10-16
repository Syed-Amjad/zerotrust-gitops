# ===========================================================================
# UNIT TESTS FOR THE POLICY ITSELF. Run with `conftest verify` or `opa test`.
#
# A policy that is never tested is a policy you hope works. The specific
# failure these guard against is the one described at the top of workloads.rego:
# in Rego, indexing a missing key yields UNDEFINED, and an undefined condition
# in a `deny` body means the rule DOES NOT FIRE. So the naive spelling of
# every rule here passes on exactly the manifests that omit the field being
# checked — a policy that reports clean because it inspected nothing.
#
# Each rule therefore gets at least two tests: one input that must be refused,
# and one that must pass. The second is not a formality. A rule that denies
# everything is as useless as one that denies nothing, and far easier to ship
# by accident, because the failing CI run looks like the policy working.
# ===========================================================================
package main

import rego.v1

# A compliant Deployment: digest-pinned, read-only root, resources declared,
# pod-level seccomp. Everything in workloads/ should look like this.
good_deploy := {
	"kind": "Deployment",
	"metadata": {"name": "api"},
	"spec": {"template": {"spec": {
		"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
		"containers": [{
			"name": "api",
			"image": "ghcr.io/syed-amjad/zt-api@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			"securityContext": {"readOnlyRootFilesystem": true, "allowPrivilegeEscalation": false},
			"resources": {
				"requests": {"cpu": "50m", "memory": "96Mi"},
				"limits": {"memory": "192Mi"},
			},
		}],
	}}},
}

test_compliant_deployment_passes if {
	count(deny) == 0 with input as good_deploy
}

# --- digest pinning -------------------------------------------------------

test_tag_reference_is_denied if {
	d := json.patch(good_deploy, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/image",
		"value": "ghcr.io/syed-amjad/zt-api:v1",
	}])
	count(deny) == 1 with input as d
}

test_latest_tag_is_denied if {
	d := json.patch(good_deploy, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/image",
		"value": "ghcr.io/syed-amjad/zt-api:latest",
	}])
	count(deny) == 1 with input as d
}

# --- privileged -----------------------------------------------------------

test_privileged_is_denied if {
	d := json.patch(good_deploy, [{
		"op": "add",
		"path": "/spec/template/spec/containers/0/securityContext/privileged",
		"value": true,
	}])
	count(deny) == 1 with input as d
}

# --- read-only root filesystem --------------------------------------------

test_writable_rootfs_is_denied if {
	d := json.patch(good_deploy, [{
		"op": "replace",
		"path": "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
		"value": false,
	}])
	count(deny) == 1 with input as d
}

# THE IMPORTANT ONE. An ABSENT field, not a false one.
#
# This is the test that catches the undefined-means-no-deny trap. A rule
# written as `c.securityContext.readOnlyRootFilesystem != true` passes the
# test above (the key exists and is false) and FAILS this one (the key is
# missing, so the comparison is undefined and the rule never fires) — which is
# the real-world case, since omitting a field is far more common than setting
# it to false.
test_missing_securitycontext_is_denied if {
	d := json.patch(good_deploy, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/securityContext",
	}])
	count(deny) > 0 with input as d
}

# --- resources ------------------------------------------------------------

test_missing_memory_limit_is_denied if {
	d := json.patch(good_deploy, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/resources/limits",
	}])
	count(deny) == 1 with input as d
}

test_missing_resources_entirely_is_denied if {
	d := json.patch(good_deploy, [{
		"op": "remove",
		"path": "/spec/template/spec/containers/0/resources",
	}])
	count(deny) == 3 with input as d
}

# A CPU limit is NOT required, and this test is what stops someone "tidying"
# that asymmetry away. See the reasoning in
# policies/kyverno/04-require-resources.yaml.
test_no_cpu_limit_is_fine if {
	count(deny) == 0 with input as good_deploy
}

# --- seccomp --------------------------------------------------------------

test_missing_pod_level_seccomp_is_denied if {
	d := json.patch(good_deploy, [{
		"op": "remove",
		"path": "/spec/template/spec/securityContext",
	}])
	count(deny) == 1 with input as d
}

# Per-CONTAINER seccomp does not satisfy the rule, because the injected
# sidecar would not inherit it.
test_container_level_seccomp_does_not_satisfy_pod_rule if {
	d := json.patch(good_deploy, [
		{"op": "remove", "path": "/spec/template/spec/securityContext"},
		{
			"op": "add",
			"path": "/spec/template/spec/containers/0/securityContext/seccompProfile",
			"value": {"type": "RuntimeDefault"},
		},
	])
	count(deny) == 1 with input as d
}

# --- namespaces -----------------------------------------------------------

test_namespace_without_psa_label_is_denied if {
	count(deny) == 1 with input as {
		"kind": "Namespace",
		"metadata": {"name": "sloppy", "labels": {"istio-injection": "enabled"}},
	}
}

test_namespace_with_restricted_psa_passes if {
	count(deny) == 0 with input as {
		"kind": "Namespace",
		"metadata": {"name": "zt-prod", "labels": {"pod-security.kubernetes.io/enforce": "restricted"}},
	}
}

test_psa_privileged_namespace_warns_but_does_not_deny if {
	ns := {
		"kind": "Namespace",
		"metadata": {"name": "zt-psa-off", "labels": {"pod-security.kubernetes.io/enforce": "privileged"}},
	}
	count(deny) == 0 with input as ns
	count(warn) == 1 with input as ns
}

# --- a non-workload object must be ignored entirely -----------------------
#
# Guards against a helper that matches too broadly. A ServiceAccount has no
# containers and no pod spec, and a rule that fires on it would make every
# manifest set in the repository fail for a reason that has nothing to do with
# security.
test_serviceaccount_is_ignored if {
	count(deny) == 0 with input as {"kind": "ServiceAccount", "metadata": {"name": "api"}}
}
