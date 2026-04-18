# Ported from checkmarx-kics: athena_database_not_encrypted.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_athena_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-ATHENA-01",
	"name": "AWS Athena Database should be encrypted",
	"description": "AWS Athena Database should have encryption_configuration defined to ensure data at rest is encrypted.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "athena", "encryption", "security"],
}

findings contains finding if {
	some r in tf.resources("aws_athena_database")
	not tf.has_sub_block(r.block, "encryption_configuration")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_athena_database %q is missing encryption_configuration.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}
