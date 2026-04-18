# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/dnssec_using_rsasha1

package vulnetix.rules.kics_tf_gcp_dns_dnssec_rsasha1

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-027",
	"name": "Cloud DNS DNSSEC uses weak RSASHA1 algorithm",
	"description": "Cloud DNS DNSSEC should use strong algorithms like RSASHA256 or RSASHA512 instead of RSASHA1.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-326"],
	"tags": ["terraform", "gcp", "dns", "dnssec", "cryptography"],
}

findings contains finding if {
	some r in terraform.resources("google_dns_managed_zone")
	some dnssec_block in terraform.sub_blocks(r.block, "dnssec_config")
	some default_block in terraform.sub_blocks(dnssec_block, "default_key_specs")
	algo := terraform.string_attr(default_block, "algorithm")
	algo in {"rsasha1", "RSASHA1"}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DNS managed zone %q uses weak RSASHA1 algorithm for DNSSEC", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_dns_managed_zone.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_dns_managed_zone")
	some dnssec_block in terraform.sub_blocks(r.block, "dnssec_config")
	some zone_block in terraform.sub_blocks(dnssec_block, "zone_signing_keys")
	algo := terraform.string_attr(zone_block, "algorithm")
	algo in {"rsasha1", "RSASHA1"}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DNS managed zone %q uses weak RSASHA1 algorithm for zone signing", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_dns_managed_zone.%s", [r.name]),
	}
}
