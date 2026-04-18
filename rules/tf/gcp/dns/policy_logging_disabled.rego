# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_dns_policy_logging_disabled

package vulnetix.rules.kics_tf_gcp_dns_logging_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-048",
	"name": "DNS policy logging is disabled",
	"description": "DNS policies should have DNS logging enabled for security monitoring and audit purposes.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["terraform", "gcp", "dns", "logging"],
}

findings contains finding if {
	some r in terraform.resources("google_dns_policy")
	not terraform.has_sub_block(r.block, "logging")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DNS policy %q does not have logging configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_dns_policy.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_dns_policy")
	subs := terraform.sub_blocks(r.block, "logging")
	count(subs) > 0
	some sub in subs
	terraform.is_false(sub, "enable_logging")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DNS policy %q has logging disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_dns_policy.%s", [r.name]),
	}
}
