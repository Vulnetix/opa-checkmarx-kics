# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_compute_ssl_policy_weak_cipher_in_use

package vulnetix.rules.kics_tf_gcp_ssl_policy_weak_cipher

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-044",
	"name": "SSL policy uses weak cipher suites",
	"description": "SSL policies should use secure cipher suites and not allow weak algorithms like RC4 or 3DES.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-326"],
	"tags": ["terraform", "gcp", "network", "ssl", "tls", "cipher"],
}

weak_profiles := {"COMPATIBLE", "custom"}

findings contains finding if {
	some r in terraform.resources("google_compute_ssl_policy")
	profile := terraform.string_attr(r.block, "profile")
	profile in weak_profiles
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SSL policy %q uses weak cipher profile %q", [r.name, profile]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_compute_ssl_policy.%s", [r.name]),
	}
}
