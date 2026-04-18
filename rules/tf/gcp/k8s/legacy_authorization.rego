# Ported from checkmarx-kics: gke_legacy_authorization_enabled.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_gcp_k8s_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-GCP-K8S-01",
	"name": "GKE Legacy Authorization should be disabled",
	"description": "GKE clusters should not have legacy ABAC (Attribute-Based Access Control) enabled. Legacy ABAC is a less secure authentication method than IAM.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "k8s", "kubernetes", "legacy", "authorization", "security"],
}

findings contains finding if {
	some r in tf.resources("google_container_cluster")
	tf.bool_attr(r.block, "enable_legacy_abac") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_container_cluster %q has enable_legacy_abac = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
