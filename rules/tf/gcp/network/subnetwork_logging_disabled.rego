# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_compute_subnetwork_logging_disabled

package vulnetix.rules.kics_tf_gcp_subnetwork_logging_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-046",
	"name": "Subnetwork VPC flow logging is disabled",
	"description": "VPC subnetworks should have flow logging enabled for network monitoring and security analysis.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["terraform", "gcp", "network", "vpc", "logging"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_subnetwork")
	# Check if log_config is missing or disabled
	not terraform.has_sub_block(r.block, "log_config")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Subnetwork %q does not have VPC flow logging enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_subnetwork.%s", [r.name]),
	}
}
