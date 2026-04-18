# Ported from checkmarx-kics: cluster_without_network_policy_support_enabled.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_gcp_k8s_02

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-GCP-K8S-02",
	"name": "GKE Network Policy should be enabled",
	"description": "GKE clusters should have network_policy enabled. Network policy allows segmentation of the cluster network to restrict communication between pods.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "k8s", "kubernetes", "network policy", "security"],
}

findings contains finding if {
	some r in tf.resources("google_container_cluster")
	not tf.has_sub_block(r.block, "network_policy")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_container_cluster %q is missing network_policy block.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

findings contains finding if {
	some r in tf.resources("google_container_cluster")
	tf.has_sub_block(r.block, "network_policy")
	policy_blocks := tf.sub_blocks(r.block, "network_policy")
	count(policy_blocks) > 0
	policy_block := policy_blocks[0]
	tf.bool_attr(policy_block, "enabled") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_container_cluster %q has network_policy.enabled = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}
