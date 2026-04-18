# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/pod_security_policy_disabled

package vulnetix.rules.kics_tf_gcp_gke_pod_security_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-015",
	"name": "GKE cluster pod security policy is disabled",
	"description": "GKE clusters should have pod security policy enabled to restrict what pods can do.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "pod-security"],
}

# Check if pod_security_policy_config is missing
findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	not terraform.has_sub_block(r.block, "pod_security_policy_config")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q does not have pod_security_policy_config configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}

# Check if pod_security_policy_config is disabled
findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	subs := terraform.sub_blocks(r.block, "pod_security_policy_config")
	count(subs) > 0
	some sub in subs
	terraform.is_false(sub, "enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has pod_security_policy_config disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
