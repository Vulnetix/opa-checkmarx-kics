# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/os_login_disabled

package vulnetix.rules.kics_tf_gcp_os_login_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-035",
	"name": "OS Login is disabled at project level",
	"description": "OS Login should be enabled at the project level to manage SSH access to VM instances using IAM roles.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "compute", "ssh", "os-login"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_project_metadata")
	not terraform.has_key(r.block, "enable-oslogin")
	finding := {
		"rule_id": metadata.id,
		"message": "Compute project metadata does not have OS Login enabled",
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_project_metadata.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_compute_project_metadata")
	val := terraform.string_attr(r.block, "enable-oslogin")
	val == "FALSE"
	finding := {
		"rule_id": metadata.id,
		"message": "Compute project metadata has OS Login disabled",
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_project_metadata.%s", [r.name]),
	}
}
