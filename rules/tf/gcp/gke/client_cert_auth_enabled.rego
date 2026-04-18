# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/legacy_client_certificate_auth_enabled

package vulnetix.rules.kics_tf_gcp_gke_client_cert_auth

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-036",
	"name": "GKE cluster has legacy client certificate authentication enabled",
	"description": "GKE clusters should not use legacy client certificate authentication which is less secure than OAuth2 tokens.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-287"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "authentication"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	some master_block in terraform.sub_blocks(r.block, "master_auth")
	not terraform.has_sub_block(master_block, "client_certificate_config")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q master_auth does not have client_certificate_config configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	some master_block in terraform.sub_blocks(r.block, "master_auth")
	some cert_block in terraform.sub_blocks(master_block, "client_certificate_config")
	terraform.bool_attr(cert_block, "issue_client_certificate") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has client certificate authentication enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
