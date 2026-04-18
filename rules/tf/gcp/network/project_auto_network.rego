# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_project_auto_create_network_disabled

package vulnetix.rules.kics_tf_gcp_project_auto_network

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-037",
	"name": "Project has auto-create network disabled",
	"description": "GCP projects should have auto_create_network disabled to prevent automatic creation of the default VPC network.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "project", "network"],
}

# This rule checks that auto_create_network is explicitly set to false
findings contains finding if {
	some r in terraform.resources("google_project")
	terraform.is_not_false(r.block, "auto_create_network")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GCP project %q does not have auto_create_network explicitly disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_project.%s", [r.name]),
	}
}
