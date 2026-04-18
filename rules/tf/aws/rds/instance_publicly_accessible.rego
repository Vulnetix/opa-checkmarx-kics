# Ported from checkmarx-kics: rds_db_instance_publicly_accessible.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_rds_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-RDS-01",
	"name": "AWS RDS DB Instance should not be publicly accessible",
	"description": "AWS RDS DB instances should not have publicly_accessible enabled, as this exposes the database to the internet.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds", "public", "database", "security"],
}

findings contains finding if {
	some r in tf.resources("aws_db_instance")
	tf.bool_attr(r.block, "publicly_accessible") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_db_instance %q has publicly_accessible = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
