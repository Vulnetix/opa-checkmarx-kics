# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_compute_subnetwork_with_private_google_access_disabled

package vulnetix.rules.kics_tf_gcp_private_google_access_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-047",
	"name": "Subnetwork private Google access is disabled",
	"description": "VPC subnetworks should have private Google access enabled to allow VMs with only internal IPs to reach Google APIs.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "network", "vpc"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_subnetwork")
	terraform.is_false(r.block, "private_ip_google_access")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Subnetwork %q does not have private Google access enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_subnetwork.%s", [r.name]),
	}
}
