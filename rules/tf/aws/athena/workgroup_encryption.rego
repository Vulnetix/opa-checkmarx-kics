# Ported from checkmarx-kics: athena_workgroup_not_encrypted.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_athena_02

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-ATHENA-02",
	"name": "AWS Athena Workgroup should have encryption enabled",
	"description": "AWS Athena Workgroup should have encryption_configuration defined in the result_configuration to ensure query results are encrypted.",
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

# Missing configuration block
findings contains finding if {
	some r in tf.resources("aws_athena_workgroup")
	not tf.has_sub_block(r.block, "configuration")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_athena_workgroup %q is missing configuration block with encryption.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

findings contains finding if {
	some r in tf.resources("aws_athena_workgroup")
	tf.has_sub_block(r.block, "configuration")
	config_blocks := tf.sub_blocks(r.block, "configuration")
	count(config_blocks) > 0
	not regex.match(`(?s)result_configuration(?i)\s*\{`, config_blocks[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_athena_workgroup %q configuration is missing result_configuration with encryption.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}

findings contains finding if {
	some r in tf.resources("aws_athena_workgroup")
	not regex.match(`(?s)encryption_configuration`, r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_athena_workgroup %q result_configuration is missing encryption_configuration.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}
