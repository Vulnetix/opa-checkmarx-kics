# Ported from checkmarx-kics: amazon_dms_replication_instance_is_publicly_accessible.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_aws_dms_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-AWS-DMS-01",
	"name": "AWS DMS Replication Instance should not be publicly accessible",
	"description": "AWS DMS Replication Instance should not have publicly_accessible enabled, as this exposes the instance to the internet.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "dms", "public", "security"],
}

findings contains finding if {
	some r in tf.resources("aws_dms_replication_instance")
	tf.bool_attr(r.block, "publicly_accessible") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_dms_replication_instance %q has publicly_accessible = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
