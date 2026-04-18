# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/cloud_dns_without_dnssec

package vulnetix.rules.kics_tf_gcp_dns_dnssec_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-026",
	"name": "Cloud DNS managed zone DNSSEC is disabled",
	"description": "Cloud DNS managed zones should have DNSSEC enabled to prevent DNS spoofing and cache poisoning attacks.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-345"],
	"tags": ["terraform", "gcp", "dns", "dnssec"],
}

# Check if dnssec_config is missing
findings contains finding if {
	some r in terraform.resources("google_dns_managed_zone")
	not terraform.has_sub_block(r.block, "dnssec_config")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DNS managed zone %q does not have dnssec_config configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_dns_managed_zone.%s", [r.name]),
	}
}

# Check if dnssec_config state is not "on"
findings contains finding if {
	some r in terraform.resources("google_dns_managed_zone")
	subs := terraform.sub_blocks(r.block, "dnssec_config")
	count(subs) > 0
	some sub in subs
	state := terraform.string_attr(sub, "state")
	state != "on"
	state != ""
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DNS managed zone %q has DNSSEC state set to %q instead of 'on'", [r.name, state]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_dns_managed_zone.%s", [r.name]),
	}
}
