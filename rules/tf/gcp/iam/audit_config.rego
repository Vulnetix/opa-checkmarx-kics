# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/iam_audit_not_properly_configured

package vulnetix.rules.kics_tf_gcp_iam_audit_config

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-051",
	"name": "IAM audit config is not properly configured",
	"description": "IAM audit configuration should cover all services and include DATA_READ, DATA_WRITE, and ADMIN_READ log types without exemptions.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["terraform", "gcp", "iam", "audit", "logging"],
}

findings contains finding if {
	some r in terraform.resources("google_project_iam_audit_config")
	service := terraform.string_attr(r.block, "service")
	service != "allServices"
	service != ""
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM audit config %q does not cover all services (service=%q)", [r.name, service]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_project_iam_audit_config.%s", [r.name]),
	}
}
